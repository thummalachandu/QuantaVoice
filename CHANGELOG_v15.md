# v15 security backend and QNu preparation update

## Added

- `backend_lab.py`: optional separate loopback server and operator console.
- `backend_store.py`: client sessions, typed request validation, canonical INR
  intent, expiry and crypto verification, SQLite atomic debit/consume.
- `backend_client.py`: separate desktop client with explicit field review,
  background API calls, launch fingerprint check and no approval route.
- `START_BACKEND_LAB.cmd` / `bootstrap_backend.py`: lightweight Windows setup.
- `requirements-backend.txt`: only two pinned crypto dependencies.
- `test_backend.py`: tests for replay, concurrent confirms, ciphertext/signature
  tampering, exact intent, cross-session use, expiry, invalid inputs, restart,
  rotation, fail-closed QNu/default mode and actual loopback HTTP requests.
- QNu collaboration and career guide, backend guide, updated inventory and GUI
  buttons. The QNu provider is unavailable by design rather than a fake adapter.

## Preserved

Existing recipient selection, microphone capture, Whisper/Vosk paths, original
seven-step presentation mode and research verifiers remain separate from the lab.
No recognition or biometric accuracy improvement is claimed for this update.

## Still requires implementation or external access

Verified speaker enrollment and calibrated ASV/CM evidence in the backend,
server-side WebAuthn relying-party enrollment, delivered OTP, real face/KYC/agent
verification, QNu SDK integration, reviewed TLS, QRNG/QKD/HSM, encrypted audit
storage, bank sandbox connectivity, institutional review and production operations.

## Security scope

The operator console is a simulated review authority on the same computer.
No client-provided identity score or “passed” flag authorizes a backend debit.
SQLite persists demo receipts but cannot resist a local user who changes the file.
Capability sessions expire in 30 minutes, pending intents in 120 seconds.
Each launch creates ephemeral keys. Restart cancels pending requests and keeps
consumed records. The client/server lab uses HTTP only on localhost.

This is a learning and prototype upgrade, not a certified banking deployment.
