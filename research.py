"""Measured ASV+CM research, G.711 transforms and clearly labeled QML experiments."""
from pathlib import Path
import json, time, math, hashlib, wave, importlib.util, platform
import numpy as np

def read_wav(path):
    with wave.open(str(path),'rb') as f:
        if f.getnchannels()!=1 or f.getsampwidth()!=2: raise ValueError('Use mono 16-bit PCM WAV recordings.')
        return np.frombuffer(f.readframes(f.getnframes()),dtype='<i2').astype(np.float32)/32768, f.getframerate()

def resample(x,rate,target):
    from scipy.signal import resample_poly
    if not len(x) or rate<=0: raise ValueError('Empty audio or invalid sample rate.')
    divisor=math.gcd(rate,target)
    return resample_poly(x,target//divisor,rate//divisor).astype(np.float32) if rate!=target else x.copy()

def channel(x,rate,codec,duration=None):
    # Crop genuine source duration first; never claim padding creates more speech.
    if duration is not None:
        if len(x)/rate+1e-6<duration: raise ValueError('Source shorter than requested duration; trial skipped.')
        x=x[:round(duration*rate)]
    if codec=='clean16': return resample(x,rate,16000)
    if codec not in ('pcm8','alaw','ulaw'): raise ValueError('Unknown channel.')
    x8=resample(x,rate,8000)
    # Same G.711 codecs and 8->16 kHz upsampler as the live telephony path (ccaas_connector),
    # so the harness measures the audio the deployed system will actually see.
    import ccaas_connector as cc
    pcm=np.clip(np.rint(x8*32768),-32768,32767).astype('<i2')
    if codec=='alaw': pcm=cc.alaw_decode(cc.alaw_encode(pcm))
    elif codec=='ulaw': pcm=cc.ulaw_decode(cc.ulaw_encode(pcm))
    # Model input is 16 kHz; bandwidth removed by the 8 kHz channel is not restored.
    return cc.to_model_audio(pcm)

class Engines:
    def __init__(self,config):
        try:
            import torch
            from speechbrain.inference.speaker import EncoderClassifier
        except ImportError as exc: raise RuntimeError('Research dependencies missing. Run: python run_research.py --install-research.') from exc
        self.torch=torch; self.device='cpu'; self.config=config
        self.ecapa=EncoderClassifier.from_hparams(source='speechbrain/spkrec-ecapa-voxceleb',
            savedir=str(Path(__file__).resolve().parent/'ecapa'),run_opts={'device':'cpu'})
        repo=Path(config['aasist_repo']).resolve()
        model_file=repo/'models'/'AASIST.py'; weight=repo/'models'/'weights'/'AASIST.pth'
        if not model_file.is_file() or not weight.is_file(): raise ValueError('Provide the official AASIST repository with its pretrained weights.')
        digest=hashlib.sha256(weight.read_bytes()).hexdigest()
        if digest!=config['aasist_sha256'].strip().lower(): raise ValueError('AASIST weight hash does not match the configured checkpoint.')
        cfg=json.loads((repo/'config'/'AASIST.conf').read_text(encoding='utf-8'))['model_config']; self.n=cfg['nb_samp']
        spec=importlib.util.spec_from_file_location('qv_official_aasist',model_file)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.cm=module.Model(cfg).to(self.device)
        self.cm.load_state_dict(torch.load(weight,map_location='cpu',weights_only=True)); self.cm.eval()
        self.weight_hash=digest
    def score(self,enroll,probe):
        t=self.torch
        if len(enroll)<16000 or len(probe)<1600: raise ValueError('Need at least 1 s enrollment and 0.1 s probe.')
        if np.max(np.abs(enroll))<1e-5 or np.max(np.abs(probe))<1e-5: raise ValueError('Silent audio is not a valid identity trial.')
        start=time.perf_counter()
        with t.no_grad():
            e=self.ecapa.encode_batch(t.tensor(enroll.copy()).unsqueeze(0)).flatten()
            p=self.ecapa.encode_batch(t.tensor(probe.copy()).unsqueeze(0)).flatten()
            asv=float(t.nn.functional.cosine_similarity(e,p,dim=0))
            asv_ms=(time.perf_counter()-start)*1000
            # Official fixed-length baseline: repeat short probes, crop long ones.
            fixed=np.tile(probe,math.ceil(self.n/len(probe)))[:self.n]
            cm_start=time.perf_counter(); _,logits=self.cm(t.tensor(fixed.copy()).unsqueeze(0))
            cm=float(logits[0,1]-logits[0,0])
            cm_ms=(time.perf_counter()-cm_start)*1000
        if not math.isfinite(asv) or not math.isfinite(cm): raise ValueError('Model returned a nonfinite score.')
        return {'asv':asv,'cm':cm,'asv_ms':asv_ms,'cm_ms':cm_ms,'total_ms':asv_ms+cm_ms,
                'speech_seconds':len(probe)/16000,'cm_input_seconds':self.n/16000,
                'cm_padding':'repeat' if len(probe)<self.n else 'none_or_crop'}

_ENGINE=None

def score_live(raw,rate,config_path):
    global _ENGINE
    config=json.loads(Path(config_path).read_text(encoding='utf-8'))
    for k in ('asv_threshold','cm_threshold','thresholds_from_dev'):
        if k not in config: raise ValueError('Calibrate thresholds on a separate development set; config missing '+k)
    if config['thresholds_from_dev'] is not True: raise ValueError('Development-set threshold calibration must be recorded first.')
    thresholds=[float(config[k]) for k in ('asv_threshold','cm_threshold')]
    if not all(math.isfinite(v) for v in thresholds): raise ValueError('Thresholds must be finite.')
    if _ENGINE is None or _ENGINE.config!=config: _ENGINE=Engines(config)
    enroll,er=read_wav(config['enrollment_wav'])
    probe=np.frombuffer(raw,dtype='<i2').astype(np.float32)/32768
    scores=_ENGINE.score(channel(enroll,er,'clean16'),channel(probe,rate,config.get('live_channel','clean16')))
    scores['passed']=scores['asv']>=thresholds[0] and scores['cm']>=thresholds[1]
    return scores

def rates(scores,positive,threshold):
    s=np.asarray(scores,float); y=np.asarray(positive,bool)
    if not y.any() or y.all(): raise ValueError('Both classes are required.')
    return float(np.mean(s[y]<threshold)),float(np.mean(s[~y]>=threshold))

def eer(scores,positive):
    s=np.asarray(scores,float)
    if not np.isfinite(s).all(): raise ValueError('Nonfinite score.')
    thresholds=np.r_[np.inf,np.unique(s),-np.inf]
    points=[(*rates(s,positive,x),x) for x in thresholds]
    miss,fa,thr=min(points,key=lambda v:abs(v[0]-v[1]))
    return {'eer_nearest':(miss+fa)/2,'miss':miss,'false_accept':fa,'threshold':float(thr) if math.isfinite(thr) else None}

def tandem_metrics(rows,asv_threshold,cm_threshold,cost):
    # Actual joint decisions; no independence approximation between ASV and CM.
    if any(not math.isfinite(float(v)) or v<0 for group in ('prior','cost') for v in cost[group].values()): raise ValueError('Costs and priors must be finite and nonnegative.')
    if not math.isclose(sum(cost['prior'].values()),1.,abs_tol=1e-6): raise ValueError('Priors must sum to one.')
    classes={k:[r for r in rows if r['label']==k] for k in ('target','nontarget','spoof')}
    if any(not v for v in classes.values()): return {'status':'need target, nontarget and spoof trials'}
    errors={}
    for k,records in classes.items():
        accepted=np.array([r['asv']>=asv_threshold and r['cm']>=cm_threshold for r in records])
        errors[k]=float(np.mean(~accepted if k=='target' else accepted))
    joint=sum(cost['prior'][k]*cost['cost'][k]*errors[k] for k in classes)
    # ASV-constrained t-DCF: C0 + C1*Pmiss_cm + C2*Pfa_cm.
    pm_asv=float(np.mean([r['asv']<asv_threshold for r in classes['target']]))
    pfa_asv=float(np.mean([r['asv']>=asv_threshold for r in classes['nontarget']]))
    pfa_sp=float(np.mean([r['asv']>=asv_threshold for r in classes['spoof']]))
    prior=cost['prior']; c=cost['cost']
    c0=prior['target']*c['target']*pm_asv+prior['nontarget']*c['nontarget']*pfa_asv
    c1=prior['target']*c['target']-c0; c2=prior['spoof']*c['spoof']*pfa_sp
    result={'joint_error_rates':errors,'joint_cost':joint}
    if c1<0 or c0+min(c1,c2)<=0:
        result['tdcf_status']='Invalid/degenerate cost model for normalized t-DCF'; return result
    bona=classes['target']+classes['nontarget']; spoof=classes['spoof']
    def dcf(th):
        miss=np.mean([r['cm']<th for r in bona]); fa=np.mean([r['cm']>=th for r in spoof])
        return float((c0+c1*miss+c2*fa)/(c0+min(c1,c2)))
    result['normalized_tdcf']=dcf(cm_threshold)
    result['min_tdcf_descriptive_only']=min(dcf(th) for th in [float('inf'),float('-inf'),*(r['cm'] for r in rows)])
    return result

def evaluate(manifest_path,config_path,output_path):
    manifest_path=Path(manifest_path).resolve(); trials=json.loads(manifest_path.read_text(encoding='utf-8'))
    config=json.loads(Path(config_path).read_text(encoding='utf-8'))
    rows=[]; speakers={}; sources={}; audio_sources={}
    for trial in trials:
        if trial['label'] not in ('target','nontarget','spoof') or trial['split'] not in ('train','dev','test'): raise ValueError('Invalid trial label or split.')
        for field in ('speaker_id','enrollment_speaker_id','source_id'):
            store=speakers if field!='source_id' else sources
            key=trial[field]
            if key in store and store[key]!=trial['split']: raise ValueError(field+' overlaps splits: '+key)
            store[key]=trial['split']
        for field in ('enrollment_wav','probe_wav'):
            digest=hashlib.sha256((manifest_path.parent/trial[field]).read_bytes()).hexdigest()
            if digest in audio_sources and audio_sources[digest]!=trial['split']:
                raise ValueError('Identical audio file occurs in multiple splits.')
            audio_sources[digest]=trial['split']
    engine=Engines(config)
    for trial in trials:
        enroll,er=read_wav(manifest_path.parent/trial['enrollment_wav'])
        probe,pr=read_wav(manifest_path.parent/trial['probe_wav'])
        enroll=channel(enroll,er,'clean16')
        for codec in ('clean16','pcm8','alaw','ulaw'):
            for duration in config.get('durations',[1,2,3,5]):
                row={k:trial[k] for k in ('trial_id','speaker_id','enrollment_speaker_id','source_id','label','language','split')}
                row.update(codec=codec,duration=duration)
                try:
                    transformed=channel(probe,pr,codec,float(duration))
                    row.update(engine.score(enroll,transformed),status='measured')
                except ValueError as exc: row.update(status='skipped',reason=str(exc))
                rows.append(row)
    report={'environment':{'python':platform.python_version(),'platform':platform.platform(),'device':'cpu'},
            'aasist_sha256':engine.weight_hash,'pipeline':'serial ECAPA plus AASIST, not a jointly trained architecture',
            'timing':'Includes enrollment embedding on each trial; excludes model load, codec transform, UI, capture and payment network.',
            'cost_model':config.get('cost_model'),'rows':rows,'groups':[]}
    measured=[r for r in rows if r['status']=='measured']
    for key in sorted({(r['split'],r['language'],r['codec'],r['duration']) for r in measured}):
        group=[r for r in measured if (r['split'],r['language'],r['codec'],r['duration'])==key]
        item=dict(zip(('split','language','codec','duration'),key)); item['n']=len(group)
        item['latency_ms']={q:float(np.percentile([r['total_ms'] for r in group],p)) for q,p in [('p50',50),('p95',95)]}
        try: item['cm_eer']=eer([r['cm'] for r in group],[r['label']!='spoof' for r in group])
        except ValueError: item['cm_eer']='insufficient classes'
        bona=[r for r in group if r['label']!='spoof']
        try: item['asv_eer']=eer([r['asv'] for r in bona],[r['label']=='target' for r in bona])
        except ValueError: item['asv_eer']='insufficient classes'
        if config.get('thresholds_from_dev') is True and 'cost_model' in config:
            item['tandem']=tandem_metrics(group,float(config['asv_threshold']),float(config['cm_threshold']),config['cost_model'])
        report['groups'].append(item)
    Path(output_path).write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    return report

def quantum_analysis(report_path,output_path):
    """Two-qubit statevector kernel vs classical RBF; no quantum advantage claim."""
    from qiskit import QuantumCircuit
    from qiskit.quantum_info import Statevector
    from sklearn.svm import SVC
    data=json.loads(Path(report_path).read_text(encoding='utf-8'))['rows']
    train=[r for r in data if r.get('status')=='measured' and r['split']=='train']
    test=[r for r in data if r.get('status')=='measured' and r['split']=='test']
    if not train or not test: raise ValueError('Measured train and test rows required; no synthetic scores are generated.')
    if {r['speaker_id'] for r in train}&{r['speaker_id'] for r in test}: raise ValueError('Speaker leakage between train and test.')
    if {r.get('enrollment_speaker_id') for r in train}&{r.get('enrollment_speaker_id') for r in test}: raise ValueError('Enrollment speaker leakage between train and test.')
    if len(train)>300 or len(test)>300: raise ValueError('Use a predefined subset of at most 300 rows per split for this small kernel experiment.')
    y=np.array([r['label']=='target' for r in train]); yt=np.array([r['label']=='target' for r in test])
    if len(set(y))<2 or len(set(yt))<2: raise ValueError('Both target and negative trials required in each split.')
    x=np.array([[r['asv'],r['cm']] for r in train]); z=np.array([[r['asv'],r['cm']] for r in test])
    mean=x.mean(0); scale=np.maximum(x.std(0),1e-6)
    x=np.clip((x-mean)/scale,-3,3)*np.pi/3; z=np.clip((z-mean)/scale,-3,3)*np.pi/3
    def state(row):
        q=QuantumCircuit(2); q.ry(float(row[0]),0); q.ry(float(row[1]),1); q.cx(0,1)
        q.rz(float(row[0]*row[1]),1)
        return Statevector.from_instruction(q).data
    start=time.perf_counter(); a=np.array([state(r) for r in x]); b=np.array([state(r) for r in z])
    kernel=np.abs(a.conj()@a.T)**2; test_kernel=np.abs(b.conj()@a.T)**2
    qmodel=SVC(kernel='precomputed',C=1).fit(kernel,y); qp=qmodel.predict(test_kernel)
    elapsed=(time.perf_counter()-start)*1000
    start=time.perf_counter(); baseline=SVC(kernel='rbf',C=1).fit(x,y); bp=baseline.predict(z)
    def errors(pred):
        return {'false_accept':float(np.mean(pred[~yt])), 'false_reject':float(np.mean(~pred[yt]))}
    result={'experiment':'Simulated 2-qubit score-fusion kernel; not production security or quantum advantage',
       'features':['ECAPA cosine','AASIST logit margin'],'train_rows':len(x),'test_rows':len(z),
       'quantum_errors':errors(qp),'classical_errors':errors(bp),'quantum_sim_accuracy':float(np.mean(qp==yt)),'classical_rbf_accuracy':float(np.mean(bp==yt)),
       'quantum_sim_fit_predict_ms':elapsed,'classical_fit_predict_ms':(time.perf_counter()-start)*1000,
       'limitations':'Fixed hyperparameters; correlated channel variants; no confidence intervals; report per-speaker uncertainty separately.'}
    Path(output_path).write_text(json.dumps(result,indent=2)); return result
