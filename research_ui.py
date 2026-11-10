"""Research UI: real evidence paths never share presentation pass buttons."""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path
import os, queue, threading, json, time
from live_voice import LiveVoice
from seven_layer_demo import BG, CYAN
from contacts import add_contact, load_contacts, matches
from device_auth import gateway_authenticator
from consent_notice import NOTICE_TEXT, NOTICE_VERSION

TEST_NOTE='''RESEARCH TEST FORMAT — no real money is sent

1. Recipient: add any name, payment ID and number. Add script aliases, e.g. Chandu; चंदू; చందు.
   The directory is local and is NOT a bank-verified payee lookup.
2. English: Pay 5000 rupees to Chandu
   Hindi: चंदू को 5000 रुपये भेजो
   Telugu: చందు కి 5000 రూపాయలు పంపు
   Spanish: Paga 5000 rupias a Chandu
   German: Zahle 5000 Rupien an Chandu
   Korean: 찬두에게 5000 루피 송금해줘
   Limited command grammar; not unrestricted conversation. Review every amount and name.
3. Test microphone, record and play back; select the matching recognition model.
   Live capture does not establish that a speaker is genuine. No speech synthesis is used.
4. Research mode uses actual ASV/CM inference only if official models, a reference WAV
   and development-set thresholds are configured. Missing evidence blocks the step.
5. Device: register a LOCAL demo credential, then verify it at layer 5. Windows WebAuthn
   verifies an assertion with required user verification; it does not disclose/guarantee
   fingerprint use or establish bank identity. Windows may offer face, PIN or a security key.
6. Face matching, delivered OTP, live agent and video-KYC are NOT integrated.
   Research mode blocks those steps; presentation mode explicitly simulates them.

EVALUATION MANIFEST (JSON array, no actual results supplied)
trial_id, speaker_id, source_id, enrollment_wav, probe_wav,
enrollment_speaker_id, label: target | nontarget | spoof, language: en-IN | hi | te,
split: train | dev | test

Use consented mono 16-bit PCM WAVs and independently verified labels.
Keep speakers, source utterances and attack-generation sources separate across splits.
Include replay, TTS/voice conversion, genuine impostors, accents, noise and unseen attacks.
Codecs: clean16, pcm8, G.711 A-law, G.711 mu-law.
Durations: 1, 2, 3, 5 seconds; shorter source trials are skipped, not fabricated.
Report CM/ASV EER, joint decisions, t-DCF with explicit priors/costs and dev thresholds,
p50/p95 inference latency, hardware, cold-start time and failures by language/channel.
This harness measures serial ASV+CM, NOT a jointly trained or latency-optimized network.
AASIST repeats short probes to its fixed model length; report original duration separately.
Telephony codecs alone do not reproduce a real IVR network, packet loss or handset path.

QUANTUM ANALYSIS
ML-KEM + AES-GCM + ML-DSA: real local encryption; not voice or fingerprint verification.
2-qubit kernel: simulator experiment on measured ASV/CM scores, compared with classical RBF.
No claim of quantum advantage, deepfake immunity or banking readiness.

CLI (same Python file; see --help):
--research-template : creates a template folder next to the app
python run_research.py --evaluate manifest.json config.json report.json
python run_research.py --qml report.json quantum_report.json
python run_research.py --install-research : installs optional research inference dependencies
Hindi / Telugu / Spanish / German / Korean: choose the matching Whisper model after startup setup. Vosk alternatives require manual installation.

Sources:
https://alphacephei.com/vosk/models
https://huggingface.co/speechbrain/spkrec-ecapa-voxceleb
https://github.com/clovaai/aasist
https://github.com/Yubico/python-fido2
'''

class ResearchVoice(LiveVoice):
    def __init__(self,root):
        self.presentation=tk.BooleanVar(master=root,value=False)
        self.tasks=queue.Queue(); self.task_busy=False
        self.device=None
        super().__init__(root)
        root.title('QuantaVoice — v17 API-wired Update'); self.heading.configure(text='QuantaVoice / v17 API-wired Update')
        root.geometry(f'{min(1200,root.winfo_screenwidth()-60)}x{min(850,root.winfo_screenheight()-100)}'); root.minsize(640,480)
        try: load_contacts()
        except Exception as exc: messagebox.showwarning('Recipient directory',str(exc))
        box=self.voice_host
        self.button(box,'Add recipient / aliases',self.add_recipient).grid(row=6,column=0,columnspan=2,sticky='w')
        self.button(box,'Testing format / limitations',self.testing).grid(row=6,column=2,columnspan=3,sticky='w')
        tk.Checkbutton(box,text='Presentation scenarios (simulated checks)',variable=self.presentation,command=self.mode_changed,
            bg=BG,fg='white',selectcolor='#153a56').grid(row=7,column=0,columnspan=3,sticky='w')
        self.button(box,'Register local device',self.register_device).grid(row=7,column=3,columnspan=2,sticky='w')
        self.button(box,'Device diagnostic only (does not pay)',self.test_device).grid(row=8,column=0,columnspan=3,sticky='w')
        self.button(box,'Security inventory / guide',self.security_status).grid(row=8,column=3,columnspan=2,sticky='w')
        self.button(box,'Rotate demo crypto keys',self.rotate_crypto).grid(row=9,column=0,columnspan=3,sticky='w')
        self.button(box,'QNu collaboration / learning guide',self.partner_guide).grid(row=9,column=3,columnspan=2,sticky='w')
        self.button(box,'Open separate backend lab (simulated)',self.open_backend_lab).grid(row=10,column=0,columnspan=5,sticky='w')
        model_root=Path(__file__).resolve().parent/'models'
        self.model_paths.extend([model_root/'vosk-model-small-hi-0.22',model_root/'vosk-model-small-te-0.42'])
        self.model_paths.extend([model_root/'whisper-en',model_root/'whisper-hi',model_root/'whisper-te',model_root/'whisper-es',model_root/'whisper-de',model_root/'whisper-ko'])
        self.model_choice['values']=['Vosk Indian English (manual install)','Vosk US English','Vosk Hindi (manual install)','Vosk Telugu (manual install)',
                                     'Whisper English (local)','Whisper Hindi (local)','Whisper Telugu (local)',
                                     'Whisper Spanish (local)','Whisper German (local)','Whisper Korean (local)']
        from whisper_engine import MODEL_DIR
        if (MODEL_DIR/'model.bin').is_file(): self.model_choice.current(4)
        self.attach_gateway()
        self.root.after(100,self.poll_tasks)
        self.render()
        self.status.set('Demo only: enable Presentation scenarios to complete a simulated payment. Then record, stop, and review your command.')
    def attach_gateway(self):
        from gateway_bridge import GatewayBridge
        try: self.flow.gateway=GatewayBridge.from_environment()
        except ValueError as exc:
            # A configured-but-broken gateway must block, never silently fall back to the local payment.
            self.flow.gateway=GatewayBridge.broken(str(exc))
            messagebox.showwarning('API gateway configuration',str(exc)+' API payments are blocked until this is fixed.')
    def enable_demo(self):
        self.presentation.set(True)
        self.mode_changed()
        self.status.set('Presentation mode selected. Say: Pay Chandu five thousand rupees. Stop, review the name and amount, then complete the seven demo steps.')

    def partner_guide(self):
        win=tk.Toplevel(self.root); win.title('QNu collaboration and job learning plan')
        text=scrolledtext.ScrolledText(win,width=100,height=35,wrap='word',font=('Arial',11)); text.pack(fill='both',expand=True)
        guide=Path(__file__).resolve().parent.parent/'QNU_COLLABORATION_AND_CAREER.md'
        try: content=guide.read_text(encoding='utf-8')
        except OSError as exc: content='Guide could not be opened: '+str(exc)
        text.insert('1.0',content); text.configure(state='disabled')

    def open_backend_lab(self):
        import os, subprocess, sys
        if not messagebox.askyesno('Separate simulated backend lab',
            'This opens a separate account and client window with a terminal operator approval. '
            'It does not connect your current voice payment or QNu. No real money moves. Continue?',parent=self.root): return
        flags=subprocess.CREATE_NEW_CONSOLE if os.name=='nt' else 0
        if os.name!='nt':
            messagebox.showinfo('Terminal required','Run python backend_lab.py --demo-review from a terminal to use operator approval.',parent=self.root)
            return
        try: subprocess.Popen([sys.executable,str(Path(__file__).resolve().parent.parent/'backend_lab.py'),'--demo-review'],creationflags=flags)
        except OSError as exc: messagebox.showerror('Cannot launch backend lab',str(exc),parent=self.root)

    def security_status(self):
        from security_inventory import inventory, GUIDE
        import json
        win=tk.Toplevel(self.root); win.title('QuantaVoice security status')
        text=scrolledtext.ScrolledText(win,width=95,height=32,wrap='word')
        text.pack(fill='both',expand=True)
        text.insert('1.0',GUIDE+'\n\n'+json.dumps(inventory(),indent=2))
        text.configure(state='disabled')
    def rotate_crypto(self):
        if getattr(self,'task_busy',False):
            messagebox.showerror('Busy','Wait for the current verification task.'); return
        self.flow.lab.rotate_keys(); self.flow.reset(); self.render()
        self.status.set('New demo keys generated. Previous payment approvals invalidated. Balance unchanged.')
    def mode_changed(self):
        self.flow.reset(); self.render()
        self.status.set('Mode changed. Review the spoken payment again. Presentation mode uses simulated identity checks.' if self.presentation.get() else 'Research mode: missing verification integrations block completion. Review the payment again.')
    def testing(self):
        win=tk.Toplevel(self.root); win.title('Testing format and implementation status')
        text=scrolledtext.ScrolledText(win,width=100,height=35,wrap='word',font=('Arial',11)); text.pack(fill='both',expand=True)
        text.insert('1.0',TEST_NOTE); text.configure(state='disabled')
    def add_recipient(self,initial='',on_saved=None):
        win=tk.Toplevel(self.root); win.title('Add a local demo recipient'); win.transient(self.root); win.grab_set()
        fields={}
        for title in ('Name','Number (only last four stored)','Payment ID','Aliases separated by semicolons'):
            tk.Label(win,text=title).pack(anchor='w',padx=15,pady=3)
            entry=tk.Entry(win,width=55); entry.pack(padx=15); fields[title]=entry
        fields['Name'].insert(0,initial)
        tk.Label(win,text='Local demo only. Payment ID ownership is not bank-verified.').pack(padx=15,pady=8)
        def save():
            try:
                c=add_contact(fields['Name'].get(),fields['Number (only last four stored)'].get(),fields['Payment ID'].get(),
                    fields['Aliases separated by semicolons'].get().split(';'))
            except Exception as exc: messagebox.showerror('Cannot save',str(exc),parent=win); return
            self.flow.reset(); self.rec.delete(0,'end'); self.rec.insert(0,c.name); self.render(); win.destroy()
            self.status.set('Recipient saved. Review the payment to select and confirm this account.')
            if on_saved is not None: on_saved(c)
        tk.Button(win,text='Save recipient',command=save).pack(pady=12)
    def choose_recipient(self,name,amount):
        if not matches(name):
            self.add_recipient(name,lambda contact:self.resume_recipient(contact,amount)); return
        super().choose_recipient(name,amount)
    def resume_recipient(self,contact,amount):
        self.amt.delete(0,'end'); self.amt.insert(0,amount)
        self.choose_recipient(contact.name,amount)

    def background(self,fn,on_success):
        if self.task_busy: return
        self.task_busy=True
        def work():
            try: self.tasks.put((on_success,fn(),None))
            except Exception as exc: self.tasks.put((on_success,None,str(exc)))
        threading.Thread(target=work,daemon=True).start()
    def poll_tasks(self):
        if self.closing: return
        try:
            while True:
                callback,result,error=self.tasks.get_nowait(); self.task_busy=False
                if error: self.write(error); messagebox.showerror('Verification unavailable or rejected',error); self.render()
                else: callback(result)
        except queue.Empty: pass
        self.root.after(100,self.poll_tasks)
    def register_device(self):
        if not messagebox.askyesno('Register local demo credential','Create an authenticator credential for this local demo? This does not enroll a bank customer.'): return
        from device_auth import DeviceAuth
        if self.device is None: self.device=DeviceAuth()
        self.background(self.device.register,lambda result:messagebox.showinfo('Local registration',result))
    def test_device(self):
        from device_auth import DeviceAuth
        if self.device is None: self.device=DeviceAuth()
        self.background(lambda:self.device.verify({'purpose':'independent local device test','no_payment':True}),
            lambda result:messagebox.showinfo('Live device test',result+' No payment step was advanced.'))
    def device_verify(self):
        from device_auth import DeviceAuth
        if self.device is None: self.device=DeviceAuth()
        epoch=self.flow.revision
        intent={'revision':epoch,'recipient':self.flow.contact_id,'amount':self.flow.amount,'note':self.flow.note}
        def success(result):
            if self.flow.revision!=epoch or self.flow.stage!=4 or self.flow.blocked:
                self.write('Discarded device result for a changed payment.'); return
            self.flow.record_device_verified(); self.flow.advance('WEBAUTHN VERIFIED'); self.write(result); self.render()
        self.background(lambda:self.device.verify(intent),success)
    def voice_verify(self):
        audio=getattr(self.mic,'last_audio',None)
        if not audio or time.monotonic()-audio[2]>120:
            messagebox.showerror('Fresh audio needed','Record a live payment command within the last 120 seconds, review it, then run ASV + CM.'); return
        if self.flow.gateway is not None:
            # v17.1: ask the gateway about consent BEFORE any voice processing. Outage or no consent means no scoring.
            self.background(self.flow.consent_gate,lambda _status:self.voice_verify_consented(audio)); return
        self.voice_verify_consented(audio)
    def voice_verify_consented(self,audio):
        epoch=self.flow.revision
        from research import score_live
        import evidence as ev
        config=ev.config_path()
        def success(scores):
            if self.flow.revision!=epoch or self.flow.stage!=0 or self.flow.blocked:
                self.write('Discarded voice scores for a changed payment.'); return
            self.write('Measured research scores: '+json.dumps(scores))
            if not scores['passed']:
                try: self.flow.reject('ASV or CM score below the configured development threshold.')
                except ValueError as exc: self.write(str(exc))
            else:
                try: self.flow.record_voice_evidence(scores,ev.load_config(config))
                except ValueError as exc: self.write('Voice evidence not recorded for the API: '+str(exc))
                self.flow.advance('RESEARCH ASV + CM PASS')
            self.render()
        self.background(lambda:score_live(audio[0],audio[1],config),success)
    # ---- v17.1: privacy & biometric consent screen ----
    def privacy_dialog(self):
        f=self.flow
        if f.gateway is None: return
        top=tk.Toplevel(self.root); top.title('Privacy & biometric consent'); top.configure(bg=BG); top.geometry('720x600')
        box=scrolledtext.ScrolledText(top,wrap='word',height=18,font=('Arial',11)); box.pack(fill='both',expand=True,padx=10,pady=8)
        box.insert('1.0',NOTICE_TEXT); box.configure(state='disabled')
        state=tk.StringVar(master=self.root,value='Checking consent status...')
        tk.Label(top,textvariable=state,bg=BG,fg='#ffdf95',font=('Arial',12),wraplength=680,justify='left').pack(anchor='w',padx=10,pady=4)
        self.consent_state_var=state; self.consent_top=top
        def show(status): state.set(f.describe_consent(status)+'   (notice '+NOTICE_VERSION+')'); self.render()
        def run(fn,ask,message):
            if ask and not messagebox.askyesno('Privacy & consent',ask): return
            self.background(fn,lambda status:(self.write(message),show(status)))
        bar=tk.Frame(top,bg=BG); bar.pack(fill='x',padx=10,pady=8)
        self.button(bar,'I agree (voice verification + anti-spoofing)',lambda:run(f.consent_grant,
            'Record your consent to voice verification and anti-spoofing under notice '+NOTICE_VERSION+'?','Biometric consent recorded.')).pack(side='left',padx=4)
        self.button(bar,'Withdraw consent',lambda:run(f.consent_withdraw,
            'Withdraw consent? Voice evidence will no longer be captured or sent, and a payment waiting for confirmation will be stopped.','Biometric consent withdrawn.')).pack(side='left',padx=4)
        self.button(bar,'Erase my voice data',lambda:run(f.consent_erase,
            'Withdraw all consent and erase your stored voiceprint? Backups outside the service database are not erased.','Consent withdrawn and stored voiceprint erased.')).pack(side='left',padx=4)
        self.button(bar,'Close',top.destroy).pack(side='right',padx=4)
        self.background(f.consent_refresh,show)
    def privacy_button(self,parent):
        if self.flow.gateway is None: return
        self.button(parent,'Privacy & consent',self.privacy_dialog).pack(anchor='w',pady=5)
        self.label(parent,self.flow.describe_consent(self.flow.consent),10).pack(anchor='w')
    # ---- v17: final step through the REST gateway ----
    def api_run(self,fn,done):
        epoch=self.flow.revision
        def success(result):
            if self.flow.revision!=epoch: self.write('Discarded API result for a changed payment.'); return
            done(result); self.render()
        self.background(fn,success)
    def api_submit_clicked(self):
        def done(r):
            risk=r['risk']; self.write('API risk review: score %s, %s. %s'%(risk['score'],risk['action'],'; '.join(risk['reasons']) or 'no flags'))
        self.api_run(self.flow.api_submit,done)
    def device_register_clicked(self):
        self.api_run(lambda:self.flow.api_device_register(gateway_authenticator(self.webauthn_origin())),
                     lambda r:self.write('Device registered with the gateway (attestation: '+r['attestation']+').'))
    def device_verify_clicked(self):
        self.api_run(lambda:self.flow.api_device_verify(gateway_authenticator(self.webauthn_origin())),
                     lambda r:(self.write('Device signature VERIFIED by the gateway ('+r['attestation']+'). Step-up satisfied.'),self.render()))
    def webauthn_origin(self): return os.environ.get('QUANTAVOICE_WEBAUTHN_ORIGIN','https://localhost')
    def api_challenge_clicked(self,shown):
        def done(result):
            spoken,ttl=result; shown.set('Say these digits within %d seconds: %s'%(ttl,spoken))
        self.api_run(self.flow.api_challenge,done)
    def api_verify_clicked(self,transcript):
        text=transcript.get()
        self.api_run(lambda:self.flow.api_verify_challenge(text),
                     lambda ok:self.write('Spoken challenge '+('VERIFIED by the API.' if ok else 'FAILED. Request a new challenge.')))
    def api_status_clicked(self):
        self.api_run(self.flow.api_status,lambda status:self.write('API status: '+status+('' if status=='approved' else '. The operator must approve in the console before confirming.')))
    def api_confirm_clicked(self):
        f=self.flow
        try:
            from contacts import resolve
            where=resolve(f.contact_id).label if f.contact_id else f.recipient
        except ValueError: where=f.recipient
        if not messagebox.askyesno('Confirm through the API',f'Confirm INR {f.amount} to {where}?\nNote: {f.note or "(none)"}\nSimulated funds only.'): return
        self.api_run(f.api_confirm,lambda r:self.write('SIMULATED PAYMENT COMPLETED via API. Receipt: '+r['receipt_id']))
    def render_gateway(self):
        f=self.flow
        for w in self.panel.winfo_children(): w.destroy()
        if f.stage==8:
            self.label(self.panel,'SIMULATED PAYMENT COMPLETED (via API)',18,'#70f0be').pack(anchor='w',pady=15)
            self.label(self.panel,'Receipt: '+str(f.receipt.get('receipt_id')) if f.receipt else 'Receipt unavailable').pack(anchor='w')
            self.label(self.panel,'The gateway consumed the authorization once, after risk review, operator review and (if required) the spoken challenge. No real money moved.').pack(anchor='w',pady=10)
            return
        self.label(self.panel,f'API MODE — INR {f.amount} to {f.recipient}',14,CYAN).pack(anchor='w',pady=8)
        sent=[]
        sent.append('speaker/spoof scores from real inference' if f.voice_evidence else 'no voice evidence (the risk engine will require step-up)')
        sent.append('app-verified WebAuthn assertion' if f.device_verified else 'no device assertion')
        self.label(self.panel,'Evidence sent: '+'; '.join(sent)+'. Presentation buttons are never sent as evidence.',10).pack(anchor='w',pady=4)
        self.privacy_button(self.panel)
        self.button(self.panel,'Register this device with the gateway',self.device_register_clicked).pack(anchor='w',pady=4)
        if not f.api:
            self.button(self.panel,'Submit to API for risk review',self.api_submit_clicked).pack(anchor='w',pady=10); return
        risk=f.api['risk']
        self.label(self.panel,f"Risk score {risk['score']} → {risk['action']}. "+'; '.join(risk['reasons']),11).pack(anchor='w',pady=4)
        if f.api['step_up'] and not f.api['challenge_ok']:
            shown=tk.StringVar(master=self.root,value='Spoken challenge required before confirmation.')
            tk.Label(self.panel,textvariable=shown,bg=BG,fg='#ffdf95',font=('Arial',13),wraplength=600,justify='left').pack(anchor='w',pady=6)
            self.button(self.panel,'Verify with my device (WebAuthn, checked by the gateway)',self.device_verify_clicked).pack(anchor='w',pady=4)
            self.button(self.panel,'Get spoken challenge',lambda:self.api_challenge_clicked(shown)).pack(anchor='w',pady=4)
            heard=tk.Entry(self.panel,font=('Arial',14)); heard.pack(anchor='w',pady=4)
            self.label(self.panel,'Enter the digits as recognised from the live speaker. This build takes the text manually; a deployment must take it from speech recognition on the live call.',10).pack(anchor='w')
            self.button(self.panel,'Verify spoken challenge',lambda:self.api_verify_clicked(heard)).pack(anchor='w',pady=4)
        self.button(self.panel,'Check approval status',self.api_status_clicked).pack(anchor='w',pady=6)
        self.button(self.panel,'Confirm through API',self.api_confirm_clicked).pack(anchor='w',pady=6)
    def render(self):
        super().render()
        if not hasattr(self,'presentation'): return
        if self.flow.gateway is not None and self.flow.stage in (7,8) and not self.flow.blocked:
            self.render_gateway(); return
        if self.presentation.get():
            if self.flow.stage==0 and not self.flow.blocked:
                self.privacy_button(self.panel)
                self.button(self.panel,'Run real ASV + CM inference (evidence for the API)',self.voice_verify).pack(anchor='w',pady=5)
            if self.flow.stage==4 and not self.flow.blocked:
                self.button(self.panel,'Use actual WebAuthn instead',self.device_verify).pack(anchor='w',pady=5)
            return
        f=self.flow
        if f.stage==-1:
            self.label(self.panel,'Research mode requires additional model assets. For the local demonstration, select the button below.',12,CYAN).pack(anchor='w',pady=6)
            self.button(self.panel,'Enable simulated payment demo',self.enable_demo).pack(anchor='w',pady=8)
        if f.blocked or f.stage not in (0,2,3,4,5,6): return
        # Preserve the locked-intent header; replace only the simulated action panel.
        for w in self.panel.winfo_children(): w.destroy()
        self.label(self.panel,f'RESEARCH MODE — INR {f.amount} to {f.recipient}',14,CYAN).pack(anchor='w',pady=8)
        if f.contact_id:
            from contacts import resolve
            self.label(self.panel,resolve(f.contact_id).label,11).pack(anchor='w')
        self.label(self.panel,'Note: '+(f.note or '(none)'),11).pack(anchor='w')
        if f.stage==0:
            self.label(self.panel,'Live microphone → ECAPA speaker score + AASIST spoof score',16,CYAN).pack(pady=10)
            self.label(self.panel,'Requires official model assets, a consented reference WAV and development-set thresholds in research_config.json. Missing evidence never passes.').pack(pady=8)
            self.button(self.panel,'Run real ASV + CM inference',self.voice_verify).pack(anchor='w',pady=8)
        elif f.stage==4:
            self.label(self.panel,'Actual Windows WebAuthn verification',16,CYAN).pack(pady=10)
            self.label(self.panel,'Windows chooses the available verification method. The app does not claim fingerprint-only verification. A signature is checked locally against the registered demo credential.').pack(pady=8)
            self.button(self.panel,'Verify registered device',self.device_verify).pack(anchor='w',pady=8)
        else:
            self.label(self.panel,'NOT INTEGRATED — STEP BLOCKED',16,'#ff8d98').pack(pady=12)
            self.label(self.panel,'Real OTP delivery, face matching, agent review and video-KYC require their own integrations. Enable Presentation scenarios only to explore their explicitly simulated workflow.').pack(pady=10)
