"""Declared local inventory, not a network scanner or enterprise CBOM certification."""
import hashlib,json,platform
from pathlib import Path
from datetime import datetime,timezone
from importlib.metadata import version,PackageNotFoundError
GUIDE = '''QUANTAVOICE v17 API-WIRED UPDATE — Tummala Chandu

NEW IN v16 (all simulated funds, loopback only, no TLS)
START_API_LAB.cmd starts a REST API (API keys, rate limits, idempotency keys, signed webhooks,
OpenAPI at /v1/openapi.json), a rule-based risk engine, a one-time spoken challenge in five
languages, a signed hash-chained audit log, and the hybrid X25519 + ML-KEM-768 provider.
New modules also cover device-bound ML-DSA keys, a simulated token vault, UPI sandbox and shadow
mode, G.711 / RTP / Twilio audio ingest, entropy health tests, QKD/QRNG/HSM adapters that fail
closed, crypto-agility with downgrade protection and a CycloneDX 1.6 CBOM. See CHANGELOG_v16.md.
v17: the desktop GUI's final step can go through that API. Set QUANTAVOICE_API_URL and QUANTAVOICE_API_KEY
(or QuantaVoice_Data/gateway_config.json) and start START_API_LAB.cmd first. Only real ASV+CM scores and an
app-verified WebAuthn assertion are ever sent as evidence; presentation buttons are not, and the client never
claims the spoken challenge. If the API is down the payment is NOT made and there is no local fallback.
With no gateway configured the GUI behaves exactly as in v16. See V17_WIRING.md. Nothing here is a bank integration.

(v15 text follows)
QUANTAVOICE v15 SECURITY UPDATE

WINDOWS START
Extract the ZIP and open QuantaVoice_Desktop_Modular. Double-click START_QUANTAVOICE.cmd
for the original voice demo or START_BACKEND_LAB.cmd for the separate backend lab.
Use RUN_TESTS.cmd after the desktop setup. Read BACKEND_LAB.md for the optional lab.
First setup needs internet. No real money moves.

OPTIONAL BACKEND LAB
Separate loopback service with session capabilities, console-only simulated review,
ML-KEM/AES-GCM/ML-DSA intent protection and a persistent SQLite simulated ledger.
This original voice GUI does NOT send its payment to that backend automatically.
The backend has its own simulated account and ephemeral keys. Loopback transport
is HTTP, not TLS. Local computer ownership remains the trust boundary.
Selecting qnu fails closed: no official SDK or credentials are integrated.
The QNu collaboration / learning guide button opens the included plan.

NEW SECURITY FEATURES
ML-KEM-768 establishes a shared secret; HKDF-SHA256 derives an AES-256-GCM key.
ML-DSA-65 signs the exact payment data under a separate session signing key.
Confirm verifies encryption integrity, signature, session, active intent and expiry.
A process lock makes duplicate concurrent confirmations consume the intent once.
Rotate demo crypto keys clears outstanding intents and approvals, preserving balance.
Pending payments expire after 120 seconds. Restart loses all crypto keys and pending payments.
Keys remain in software memory. Python does not guarantee secure memory erasure.
The same local process generates and trusts these keys: no bank or remote signer identity.
The original voice workflow has no permanent receipt store or server-side ledger.
Only the separately launched backend lab persists balance and consumed receipts.

STATUS AND REPORTS
Open Security inventory / guide to view the declared local status.
RUN_TESTS.cmd runs the full automated suite after desktop setup.
For the separate backend, follow the lightweight test command in BACKEND_LAB.md.
The GUI has Security inventory / guide and Rotate demo crypto keys buttons.
The inventory declares this program's algorithms, dependency versions and source hash.
It is not automated enterprise discovery, key custody, compliance certification or migration orchestration.

PAYMENT TEST
Choose a saved exact account or add any name with its demo payment ID and aliases.
Speak 'Send 500 rupees to Chandu', then review the transcript, amount and account.
Only use presentation mode for simulated identity scenarios. Follow its labeled steps.
Research mode requires configured real ASV/CM evidence and blocks missing verifiers.
Test tampering before confirming: the balance must not change on rejection.
A successful simulated payment must debit once. Reusing the packet must fail.
Rotating keys must cancel the old reviewed payment; review a new payment afterward.
The presentation PIN/OTP and other scenarios are not banking authentication.

PHYSICAL AND MODEL TESTING STILL REQUIRED
Test Windows microphone/device authentication and actual mobile browser separately.
This Python desktop file does not run as a mobile application; the existing website is separate.
ECAPA/AASIST require trusted model files, enrollment data and calibrated thresholds.
Measure genuine/impostor/spoof outcomes separately by language, device and channel.
Use clean 16 kHz, 8 kHz PCM, G.711 A-law/mu-law and 1/2/3/5-second speech.
Keep train/development/test speakers separate; report EER, t-DCF assumptions and latency.
Passing software tests does not establish 100% speech accuracy or deepfake detection.

EXTERNAL INTEGRATION REQUIREMENTS — NOT CONNECTED
QKD: authenticated key-distribution equipment/service and supported key-management API.
QRNG: hardware or contracted entropy source, health tests and an explicit failure policy.
QNu: product access, credentials, official API documentation and a test environment.
HSM: a compatible device/service with support for the required algorithms and key lifecycle.
Hybrid TLS: compatible server and client, certificate validation and negotiated-group evidence.
No URLs or fake adapters in this release claim these services are connected.
Enterprise work additionally needs a backend, trusted identity enrollment, durable audit,
access control, backup/recovery, key revocation, monitoring and independent assessment.

SOURCES
https://csrc.nist.gov/pubs/fips/203/final
https://csrc.nist.gov/pubs/fips/204/final
https://github.com/PQClean/PQClean
'''
def inventory():
    deps={}
    for name in ['pqcrypto','cryptography','fido2','vosk','qiskit','scipy']:
        try: deps[name]=version(name)
        except PackageNotFoundError: deps[name]='not installed in this interpreter'
    source=Path(globals().get('MAIN_FILE',__file__))
    return dict(schema='quantavoice-local-inventory-1',generated=datetime.now(timezone.utc).isoformat(),
        scope='Declared Python research application; no network discovery; not enterprise CBOM',
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),python=platform.python_version(),dependencies=deps,
        crypto=[{'purpose':p,'algorithm':a,'status':'implemented locally'} for p,a in [
            ('key establishment','ML-KEM-768'),('hybrid key establishment (optional provider)','X25519 + ML-KEM-768'),('audit signatures','ML-DSA-65 hash chain'),('API webhook signatures','HMAC-SHA256'),('key derivation','HKDF-SHA256'),
            ('payment encryption','AES-256-GCM'),('payment signature','ML-DSA-65'),
            ('demo PIN hashing','scrypt'),('randomness','OS CSPRNG via secrets'),
            ('device authentication','WebAuthn ES256 verified by the gateway (v17.2); classical, not PQC'),
            ('transport','TLS 1.2/1.3 and mutual TLS via OpenSSL (lab PKI); hybrid PQ groups not verified')]],
        key_management={'storage':'process memory','rotation':'manual GUI; invalidates pending intents',
                        'trusted_signer':'same local session only','secure_erasure':'not guaranteed','hsm':False},
        external={k:'not integrated or verified' for k in ['QKD','QRNG','QNu','HSM','hybrid_PQC_TLS','bank_payment_API']},
        optional_backend={'available':True,'launch':'START_BACKEND_LAB.cmd',
            'connected_to_voice_flow':False,'ledger':'SQLite simulated account and receipts',
            'authorization':'separate console simulated review','transport':'loopback HTTP only',
            'identity_trust':'local launch capability, not bank identity','qnu_connected':False},
        v16_platform={'rest_api':'api_gateway.py + api_lab.py (loopback HTTP, or HTTPS/mTLS with lab PKI since v17.2)','risk_engine':'rule-based, uncalibrated',
            'audit_log':'hash chain + ML-DSA-65, local key','provider_connections':'QRNG, QKD, HSM not connected',
            'tokenization':'simulated, not PCI certified','payment_rails':'sandbox and shadow mode only',
            'wired_into_voice_gui':'optional: final step uses the API when a gateway is configured (V17_WIRING.md)'},
        remaining=['central key management','enterprise discovery','production audit and ledger','remote identity trust','independent security audit'],
        speech_accuracy='not established by software tests',real_payments=False)
def test_report(result):
    return dict(generated=datetime.now(timezone.utc).isoformat(),tests_run=result.testsRun,
        failures=[str(t) for t,_ in result.failures],errors=[str(t) for t,_ in result.errors],
        skipped=[{'test':str(t),'reason':reason} for t,reason in result.skipped],
        passed=result.wasSuccessful(),scope='Automated software tests; not physical device or model accuracy validation')
