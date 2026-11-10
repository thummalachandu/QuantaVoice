# v17.3 - live security demo page wired to the real engine

- New `quantavoice/live_demo_server.py` and `quantavoice/web/QuantaVoice_Live_Security_Demo.html`; launcher
  `START_LIVE_DEMO.cmd` / `live_demo_lab.py`; `bootstrap_backend.py --live-demo`. Read `LIVE_DEMO.md`.
- The page was a front-end-only mock (random scores, hard-coded accuracy claims). It now shows the result of a real
  `seven_flow` run and labels each layer REAL or SIMULATED. Added a fifth scenario, Wrong PIN x3 (real lockout).
- Fixed in the page: amount above the engine limit, an inaccurate "escalating to Layer 7" message, a static fake risk score,
  the log being wiped when a scenario button was pressed, and RESET not stopping a run in progress.
- 12 new tests in `test_live_demo.py` (engine results per scenario, honest-page checks, loopback / Host / Origin / body limits).
  The page's JavaScript was also driven in a DOM against the live server for all five scenarios and RESET (not part of the unit suite).
- `APP_VERSION` and `QuantaVoice_CBOM.json` are 17.3.
