# v17.1: biometric privacy controls (from the 50-company security review)

## Added
- `quantavoice/privacy_consent.py`
  - `ConsentLedger`: per-subject, per-purpose consent (voice_verification, anti_spoofing, audit_evidence) with expiry,
    withdrawal and an access-request history. Subject ids are HMAC-SHA256 pseudonyms; raw ids are never stored.
  - `TemplateVault`: voiceprint embeddings encrypted with AES-256-GCM under a per-subject HKDF key, bound to the subject
    through AAD. Loading requires valid consent for the stated purpose. Retention limit with auto-erase, `erase()`
    (crypto-erase) and hash-only erasure receipts.
- `quantavoice/test_privacy_consent.py`: 13 tests (consent required, withdrawal, expiry, purpose limitation, erasure,
  retention, no plaintext or raw id on disk, ciphertext swap between subjects, bit-flip detection, input validation).
- `QuantaVoice_50_Company_Security_Map.xlsx` (delivered alongside): the 50 companies mapped to 21 controls.

## Not changed
No existing file was modified. `privacy_consent.py` only needs `cryptography`, already in `requirements.txt`.

## Still open (see the Control Catalog sheet)
Real TLS/mTLS, HSM/KMS custody, PCI/ISO/SOC 2/FIPS certification, QRNG/QKD/HSM connection, calibrated ASV/CM
thresholds and measured error rates, Genesys/NICE connectors, Spanish/German/Korean command parsing, and paper findings
F1 (signature in the clear), F4 (HKDF info/AAD binding), F5, F6.

## Limits
Not legal advice or a compliance certificate. The master key lives in memory unless you pass one in. Backups and copies
outside the vault database are not erased by `erase()`. Not yet wired into the desktop GUI or the API gateway.
