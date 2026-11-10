# v17.2: consent wiring, gateway-verified devices, three more languages, real TLS (To-Do B6, B8, B10, part of B3)

Contents: (1) privacy consent wired in (B6), (2) gateway-verified WebAuthn device with transaction binding (B8), (3) Spanish,
German and Korean commands (B10), (4) TLS and mutual TLS (B3, partial). 319 tests pass; 14 GUI tests skip without a display.


## Added
- **API** (`api_gateway.py`)
  - Biometric evidence is refused unless the customer has valid consent: `asv_score` needs `voice_verification`,
    `cm_score` needs `anti_spoofing`. Missing consent returns `403 consent_required` and nothing is created or scored.
    Evidence without a `customer_ref` returns `400 customer_ref_required`.
  - Consent is checked again at confirm. A withdrawal or expiry after creation returns `403 consent_withdrawn` and the
    authorization is not consumed.
  - New endpoints: `POST /v1/consents`, `POST /v1/consents/withdraw`, `POST /v1/consents/erase`,
    `GET /v1/consents/{customer_ref}` (status and consent history, never biometric content). New scopes
    `consents:read` and `consents:write`, included in the default key scopes.
  - Consent is scoped to the API key that collected it. One partner cannot use or read another partner's consent.
  - The audit log records `consent.granted`, `consent.withdrawn`, `consent.erased` and `consent.denied` with a
    pseudonym, never the customer reference.
  - `AuthorizationService(consent=ConsentLedger, vault=TemplateVault)`. With `consent=None` behaviour is exactly v17.
- **SDK**: `grant_consent`, `withdraw_consent`, `consent_status`, `erase_customer_data`.
- **Desktop flow** (`seven_flow.py`, `gateway_bridge.py`): `consent_gate` runs before any voice scoring and fails closed
  on an outage; `consent_grant`, `consent_withdraw`, `consent_erase`. Withdrawal and erasure discard evidence already
  recorded. `api_submit` re-checks before it sends recorded evidence.
- **GUI** (`research_ui.py`, `consent_notice.py`): a "Privacy & consent" screen with the notice text, "I agree",
  "Withdraw consent" and "Erase my voice data". "Run real ASV + CM inference" no longer scores voice until the gateway
  confirms consent.
- **Lab** (`api_lab.py`): consent is enforced by default and the voiceprint vault is attached. `--no-consent` restores v17
  behaviour. Set `QUANTAVOICE_CONSENT_KEY` (64 hex characters) to keep consent across restarts; without it consent resets.
- `test_v17_1_consent_wiring.py`: 30 tests (API, scopes, isolation, expiry, withdrawal, erase, audit, SDK, flow, GUI, CBOM).

## Fixed
- `cbom.py` and `QuantaVoice_CBOM.json` still reported application version 16.0 in the v17.1 zip although the To-Do list
  marked it done. The version now comes from one constant, `cbom.APP_VERSION` (17.2), and a test checks both files.

## Not done / limits
- The gateway cannot see the customer. Consent is attested by the partner or the desktop app, not verified by QuantaVoice.
- The notice text is a draft and needs legal review per market. No lawful-basis logic, no DPDP guardian or minor handling.
- The master key is in memory unless `QUANTAVOICE_CONSENT_KEY` is supplied. Backups are not covered by erase.
- Nothing in the API or desktop app stores a voiceprint in the vault yet; erase deletes one only if a caller stored it.
- B8 (device attestation), B4/B5 (paper findings F1, F4, F5, F6), TLS, HSM and the rest of the To-Do list are unchanged.


## B8: customer device verified by the gateway (control C06)
- `device_gateway.py`: WebAuthn (FIDO2) registration and assertion verified server-side on any OS. The challenge is
  SHA-256 of a label, the transaction digest and a one-time nonce, so a signature proves this device approved this payment.
  Origin, RP id, user present, user verified, signature, one-time expiring session and a strictly increasing counter are checked.
- Attestation is optional and reported as `attested` or `unattested`. With trust roots configured, `none` and self
  attestation are refused, the certificate chain must end in your root and the leaf must be valid now. `require_attested` refuses the rest.
- API: `POST /v1/devices/register/begin|complete`, `POST /v1/authorizations/{id}/device/begin|complete` (new scope
  `devices:write`, in the default scopes). A verified device satisfies step-up. The client claim `device_bound` is still accepted
  but is not what the gateway trusts for step-up.
- Desktop: `Flow.api_device_register / api_device_verify`, GUI buttons, and `device_auth.gateway_authenticator` for Windows Hello
  or a security key. The desktop checks that the challenge commits to the payment the person reviewed before it asks the device to sign.
- `softkey.py`: a software authenticator for tests. `test_v17_2_device.py`: 26 tests.
- Limits: not tested with a real authenticator (none available in the build environment). No FIDO MDS roots shipped, no revocation
  or authenticator-certification checks. ES256 is classical, not post-quantum. Synced passkeys report counter 0, so clone detection
  is not possible for them.

## B10: Spanish, German, Korean commands (control C19)
- `command_langs.py`: strict grammar for commands, number words (Spanish, German compounds, Sino-Korean) and European digit
  grouping. Ambiguous amounts (`5,000` in German or Spanish) are refused. One payment only: `y`, `und`, `그리고` and similar are refused.
- Whisper accepts es, de, ko; the GUI lists the three models; Korean one-time challenge digits added (영/공 for zero, joined syllables).
- `test_v17_2_languages.py`: 16 tests. Phrases and number tables were written by the author of this build and have not been
  reviewed by native speakers. Speech recognition accuracy in these languages is not measured.

## B3 (partial): TLS and mutual TLS
- `api_gateway.serve(..., tls=TlsConfig(cert, key, client_ca=None, tls13_only=False))`: TLS 1.2 minimum (1.0 and 1.1 refused), TLS 1.3
  only on request, handshake in the connection thread so a stalled client cannot block others, orderly close so early error
  replies are not lost. A non-loopback bind now needs TLS.
- `sdk.Client(..., cafile, client_cert, client_key)` verifies the server certificate and host name. The desktop reads
  `QUANTAVOICE_API_CA`, `QUANTAVOICE_API_CLIENT_CERT`, `QUANTAVOICE_API_CLIENT_KEY` (or `ca_file`, `client_cert`, `client_key` in
  gateway_config.json). A bad TLS setting blocks API payments; it never falls back.
- `api_lab.py --dev-tls [--mtls]` writes a throw-away CA, server and client certificate to QuantaVoice_Data/tls. Lab only.
- `tls_dev.py`, `test_v17_2_tls.py` (21 real handshakes: wrong CA, wrong host, no client certificate, plain HTTP, TLS 1.0/1.1, stalled clients).
- Still missing for C16 (so it stays Partial): production certificates and CA, key custody, revocation, cipher policy review, and
  hybrid post-quantum key exchange. The build machine had OpenSSL 3.0.13, which has no X25519MLKEM768. A client certificate
  authenticates the transport only; the API key is still required.

## Also changed
- CBOM lists the new classical algorithms (ECDSA P-256, ECDHE). The compliance map has rows for TLS and WebAuthn.
