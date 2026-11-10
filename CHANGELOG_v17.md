# v17: from library to wired product path

## Added
- `quantavoice/evidence.py`: measured ASV/CM scores to the API's 0-1 context; each calibrated threshold maps to exactly 0.5.
- `quantavoice/gateway_bridge.py`: desktop client with short timeouts, fail-closed errors, echo verification.
- `Flow` API methods (`api_submit`, `api_challenge`, `api_verify_challenge`, `api_status`, `api_confirm`) and
  `record_voice_evidence` / `record_device_verified`; research UI panel and receipt for stage 8.
- `run_research.py` (+ `requirements-research.txt`, `research_config.example.json`): working entry point for
  `--install-research`, `--example-config`, `--evaluate`, `--qml`.
- `V17_WIRING.md`, `gateway_config.example.json`; 54 new tests in `test_v17_*.py`.

## Fixed
- API responses now echo `recipient`, `destination` and `currency`, so the desktop can verify the destination it reviewed (v16 gap).
- Research harness no longer uses `audioop` (gone in Python 3.13) and now applies the same G.711 codecs and 8 to 16 kHz upsampler as the
  live telephony path, so it measures the audio deployment will see.
- The research flags lost in the v9 modular split are restored via `run_research.py`.
- The GUI looked for `research_config.json` in `quantavoice/`; the guide documents `QuantaVoice_Data/`. Both now use the documented path.
- `Flow.reject()` no longer indexes past the seven layer states when rejecting at the final step.
- Evidence mapping: scores are no longer rounded to 6 places. A score just below its calibrated threshold used to round to exactly 0.5 and pass the engine; it now stays below 0.5 (regression test added).

## Not done
Real model scores, Windows GUI run, WebAuthn run, ASR-fed challenge transcript, TLS, bank or UPI connections,
QNu SDK, Genesys/NICE connectors, Spanish/German/Korean payment-command parsing.
