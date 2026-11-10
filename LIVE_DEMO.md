# v17.3 Live security demo (simulated funds, loopback only)

Start with `START_LIVE_DEMO.cmd` (Windows, Python 3.12). It opens `http://127.0.0.1:8790/` in your browser.
Use `python live_demo_lab.py --port 9000 --no-browser` to pick a port or skip opening the browser.

The page replays one run of the QuantaVoice engine (`seven_flow`) through its seven layers. Five scenarios:
Legitimate TX, Deepfake Attack, Voice Clone, Session Hijack, Wrong PIN x3.

## What is real and what is simulated

| Layer | Name | Kind |
|---|---|---|
| 1 | Voice + anti-spoofing | SIMULATED gate (no voice model runs) |
| 2 | PIN / passphrase | REAL: scrypt check with a real 3-try lockout |
| 3 | OTP verification | REAL: one-time code issued and verified |
| 4-7 | Face + liveness, Fingerprint / FIDO2, Agent review, Video KYC | SIMULATED gates |
| Payment | Sealed after layer 7 | REAL code (ML-KEM-768 + AES-256-GCM + ML-DSA-65) moving SIMULATED funds |

Any rejected layer blocks the payment; later layers show NOT REACHED and the simulated balance stays unchanged.
Deepfake and Voice Clone both stop at layer 1, because the engine treats speaker and anti-spoofing evidence as one gate.

## Differences from the original standalone HTML

- No `Math.random()` scores and no accuracy figures (the old page showed 98.7 percent and similar). None has been measured;
  see C20 in the 50-company map. Layers show their real result, or SIMULATED.
- The amount is 5,000 rupees, not 5,00,000: the engine caps a payment at 50,000 and the simulated balance is 50,000.
- A failed layer blocks the payment. The old page said it escalated to Video KYC, which the engine does not do.
- Opening the HTML file directly (without the engine) shows an error and no results.

## Server limits

Binds to loopback only (refuses anything else). Rejects requests whose Host header is not loopback (DNS rebinding) and
cross-site POSTs, limits the request body to 1 KB, accepts only the five scenario names, and serves a strict
Content-Security-Policy. There is no login because nothing sensitive is stored: every run uses a fresh in-memory simulated account.
