"""Generate editable research inputs, not invented experiment results."""
from pathlib import Path
import json

GUIDE='''QuantaVoice Live v9

Use Python 3.12. Main app: py -V:3.12 QuantaVoice_OneFile.py
In-app Testing format / limitations explains each payment and test step.
Research mode is the default. Missing real evidence blocks progression.
Presentation scenarios are explicitly simulated and reset all prior approvals.

FIRST TEST
Add a recipient name, masked-number source and payment ID. These are local demo
records, not verified bank identities. Add aliases in the script used by ASR.
Test microphone playback before transcription. No TTS/AI voice is generated.
Hindi: --language hi; Telugu: --language te; default: Indian English.
The native command templates are deliberately limited. Spoken numbers outside
the listed simple grammar may need manual correction. No fuzzy routing by name.
Telugu recognition is experimental: the publisher reports high error on its
listed FLEURS benchmark. Do not assume it will recognize your speech reliably.

REAL DEVICE TEST
Register local device, then Test registered device (no payment). On supported
Windows, python-fido2 calls the OS WebAuthn API. It verifies a real signature,
challenge, RP ID, origin and user-verification flag locally. Windows decides
whether to use fingerprint, face, PIN or another supported method. No raw
fingerprint enters Python. Registration is self-enrollment for a local demo,
not bank-customer identity proof. No authenticator hardware test was run here.

VOICE RESEARCH SETUP
1. Run: python run_research.py --install-research (large optional downloads).
2. Obtain the official repository and pretrained AASIST weights from
   https://github.com/clovaai/aasist . Keep models/AASIST.py,
   config/AASIST.conf and models/weights/AASIST.pth in that repository.
3. Edit config.json: absolute aasist_repo path, weight SHA-256, and consented
   enrollment_wav. In PowerShell compute the hash with:
   Get-FileHash 'C:\\path\\aasist\\models\\weights\\AASIST.pth' -Algorithm SHA256
4. ECAPA weights download from speechbrain/spkrec-ecapa-voxceleb on first inference.
   Dependencies and model inference adapters have NOT been exercised end-to-end
   in this environment. Official model compatibility and performance must be
   checked before making claims. Missing models/errors never produce a pass.
5. Create consented genuine, impostor and spoof WAV trials with verified labels.
   Use separate speaker/source groups for train, dev and test; include unseen
   attack systems. All paths in manifest.json are relative to that manifest.
6. Run: python run_research.py --evaluate manifest.json config.json report.json. It measures channel and
   duration variants, not a real phone network. File/model errors remain failures.
7. Calibrate asv_threshold and cm_threshold only on the development split.
   Set thresholds_from_dev=true only when that has actually been done.
   Cost priors in the sample config are ILLUSTRATIVE, not banking policy.
8. Copy the completed config to QuantaVoice_Data/research_config.json for the
   live ASV+CM button. Record your command with the live microphone, review it,
   then run ASV+CM. The reference WAV must have verified enrollment provenance.

MEASUREMENT LIMITS
ASV/CM are serial independent models, not a unified trained model. Reports include
original duration and AASIST repeated/cropped input length. Timing includes
reference embedding each trial but excludes model load, capture, channel
conversion, UI and any payment network. Report those times separately for a
true end-to-end latency claim. Track language, codec, handset, noise, attack,
duration, thresholds and failures. Nearest-operating-point EER is approximate.
Normalized t-DCF uses a specified fixed ASV threshold, cost assumptions and CM
error rates. Joint decision cost is also reported without an independence
assumption. Test-set min t-DCF is descriptive only; never use it to select a
production threshold. Add per-speaker bootstrap confidence intervals for a paper.

QUANTUM ANALYSIS
python run_research.py --qml report.json quantum_report.json compares a simulated 2-qubit kernel with
a classical RBF SVM on measured ASV/CM scores. Requires train/test rows and both
classes; no invented scores. Fixed settings, small sample cap and no uncertainty
estimates: an exploratory experiment, not evidence of quantum advantage.
ML-KEM + AES-GCM remains real local encryption; it cannot establish voice identity
or detect a spoof. Replacing all application logic with QML is not warranted.

VALIDATION
31 automated tests plus standalone assembly checks passed when this release was
built, covering multilingual parsing, recipient aliases, codec processing,
metrics, WebAuthn signature/challenge validation and existing payment safeguards.
Windows GUI/hardware, model inference and multilingual live accuracy are untested.
Face matching, real OTP delivery, agent and video-KYC integrations are absent;
research mode blocks their gates. There is no payment-provider integration.
No completed performance, novelty, compliance or publishability claim is made.

Sources:
https://alphacephei.com/vosk/models
https://huggingface.co/speechbrain/spkrec-ecapa-voxceleb
https://github.com/clovaai/aasist
https://github.com/Yubico/python-fido2
https://www.w3.org/TR/webauthn-3/
'''

def create_template(root):
    root=Path(root); root.mkdir(parents=True,exist_ok=True)
    config={'aasist_repo':'C:/REPLACE/aasist','aasist_sha256':'REPLACE_WITH_CHECKPOINT_SHA256',
        'enrollment_wav':'C:/REPLACE/consented_reference.wav','live_channel':'alaw',
        'asv_threshold':None,'cm_threshold':None,'thresholds_from_dev':False,'durations':[1,2,3,5],
        'cost_model':{'prior':{'target':.9405,'nontarget':.0095,'spoof':.05},
                      'cost':{'target':1.,'nontarget':10.,'spoof':10.}}}
    manifest=[{'trial_id':'REPLACE_001','speaker_id':'speaker_dev_01','enrollment_speaker_id':'speaker_dev_01',
        'source_id':'source_dev_001','enrollment_wav':'audio/reference.wav','probe_wav':'audio/probe.wav',
        'label':'target','language':'en-IN','split':'dev'}]
    files={'config.json':json.dumps(config,indent=2),'manifest.json':json.dumps(manifest,indent=2),'READ_ME.txt':GUIDE}
    for name,text in files.items():
        dest=root/name
        if not dest.exists(): dest.write_text(text,encoding='utf-8')
    return str(root)
