# v16 platform upgrade

Built from the 50-company sponsor database: what Pindrop, Veridas, the payment companies, banks and
QNu would each ask for first. All modules are in `quantavoice/` and covered by `test_v16_*.py`.

## Added

| Module | What it does |
|---|---|
| `hybrid_kex.py`, `HybridPQCProvider` | X25519 + ML-KEM-768 hybrid key establishment; `backend_lab.py --provider hybrid` |
| `api_gateway.py`, `sdk.py`, `api_lab.py` | REST API v1: API keys and scopes, rate limit, idempotency, signed webhooks with SSRF checks, OpenAPI 3, Python SDK |
| `risk_engine.py` | Transparent fraud-risk score; missing voice evidence can never allow |
| `challenge_phrase.py` | One-time spoken digits bound to the transaction (en, es, de, hi, te) |
| `device_binding.py` | Server-side relying party for device-bound ML-DSA-65 keys with replay and clone counters |
| `audit_log.py` | Hash-chained, ML-DSA-signed audit log, truncation checkpoints, JSONL and CEF export |
| `ccaas_connector.py` | G.711 mu-law/A-law (bit-exact vs reference), RTP reassembly, Twilio Media Streams adapter |
| `payment_rails.py` | UPI URI builder/parser, no-network sandbox rail, shadow-mode agreement metrics |
| `tokenization.py` | Simulated token vault, domain-bound tokens, single-use cryptograms |
| `provider_adapters.py` | SP 800-90B-style health tests, QRNG mixing, ETSI QKD 014 client, scrypt key store; QRNG/QKD/HSM fail closed |
| `crypto_agility.py` | Post-quantum-only suite negotiation with downgrade binding |
| `cbom.py` | CycloneDX 1.6 CBOM and an honest compliance map |
| `v16_demo.py` | End-to-end demo and benchmark; writes `v16_demo_results.json`, `QuantaVoice_CBOM.json` |

## Changed

`backend_store.provider_for` accepts `hybrid`; `rotate()` keeps the provider type; `bootstrap_backend.py --api`;
`requirements-backend.txt` adds numpy; security guide and inventory describe v16.

## Not done (needs outside access or more work)

QNu SDK, real QRNG/QKD/HSM, TLS, Genesys/NICE connectors, bank or UPI sandbox credentials, calibrated ASV/CM
thresholds, PCI/ISO certification, wiring the desktop voice GUI to these modules, Spanish/German/Korean
payment-command parsing.
