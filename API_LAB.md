# v16 REST API lab (simulated funds, loopback only)

Start with `START_API_LAB.cmd` (Windows, Python 3.12). Type `newkey partner1` in the operator
console to mint an API key (shown once). The server prints its port; OpenAPI is at `/v1/openapi.json`.

## Flow

1. `POST /v1/authorizations` with header `Idempotency-Key` and body
   `{recipient, destination, amount, note?, customer_ref?, context?}`.
   `context` may hold `new_payee, hour, channel, device_bound, asv_score, cm_score, challenge_verified`.
   The risk engine returns `allow`, `step_up` or `deny`. A denied request creates no intent.
2. If `step_up_required` is true: `POST /v1/authorizations/{id}/challenge` (body `{"lang":"hi"}`),
   the customer speaks the digits, then `POST .../challenge/verify` with `{challenge_id, transcript}`.
3. An operator approves in the console (`approve ID`), which is the simulated review.
4. `POST /v1/authorizations/{id}/confirm` with `{digest}` consumes it once.
5. Webhooks (`authorization.created / declined / confirmed`) carry `QuantaVoice-Signature: t=..,v1=..`
   = HMAC-SHA256(secret, "t.body"). Reject deliveries older than five minutes.

## Python SDK

```python
from sdk import Client
c = Client('http://127.0.0.1:8787', 'qvk_xxxxxxxx.yyyy')
a = c.create_authorization('Chandu', 'chandu@demo', '6000', context={'asv_score': .9, 'cm_score': .9})
```

## Limits you must keep in mind

- No TLS, loopback bind only. A production gateway needs a reviewed TLS terminator and mTLS.
- Evidence fields in `context` are asserted by the authenticated partner, not verified here.
- Risk weights are heuristics, not trained on fraud data. Set speaker thresholds from your own dev set.
- The audit signing key is in memory; `.pub` is saved so a log can be verified later. No WORM storage.
- One active intent per API key, because the backend cancels the previous intent for that session.

## Consent endpoints (v17.2)

| Method and path | Scope | Purpose |
|---|---|---|
| `POST /v1/consents` | consents:write | `{customer_ref, purposes[], notice_version, ttl_days?}` records consent |
| `POST /v1/consents/withdraw` | consents:write | `{customer_ref, purpose?}` withdraws one purpose or all |
| `POST /v1/consents/erase` | consents:write | withdraws all and erases the stored voiceprint |
| `GET /v1/consents/{customer_ref}` | consents:read | status and consent history, no biometric content |

`POST /v1/authorizations` with `asv_score` or `cm_score` needs consent for `voice_verification` or `anti_spoofing`
(403 `consent_required` otherwise) and a `customer_ref`. `--no-consent` turns enforcement off. The partner attests that the
customer agreed; the gateway cannot verify that.

## Device and TLS (v17.2)

| Method and path | Scope | Purpose |
|---|---|---|
| `POST /v1/devices/register/begin`, `/complete` | devices:write | WebAuthn registration; returns the attestation level |
| `POST /v1/authorizations/{id}/device/begin`, `/complete` | authorizations:write | WebAuthn challenge bound to the transaction digest; a verified device satisfies step-up |

TLS flags: `--dev-tls`, `--mtls`, `--tls-cert`, `--tls-key`, `--tls-client-ca`, `--tls13-only`, `--host`. Device flags:
`--webauthn-origin`, `--webauthn-rp-id`, `--attestation-root`, `--require-attested`.
