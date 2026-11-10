# Optional backend lab: Windows steps

This is a separate client/server **simulated-payment lab**, not a production
backend or a QNu integration. Your original microphone workflow remains available.

## First launch

1. Close the old app. Extract the entire updated ZIP to a new folder.
2. Open `QuantaVoice_Desktop_Modular`. Do not run inside the ZIP.
3. Double-click `START_BACKEND_LAB.cmd`. Python 3.12 is required.
4. First use creates `.venv-backend` and installs only pqcrypto and cryptography.
   No speech model download or paid API key is needed for this optional lab.
5. Keep the terminal open. A separate desktop client opens.
6. Enter `Chandu`, `chandu@demo`, and `5000`. Review exact fields before submitting.
   These are test inputs, not verified bank destinations.
7. Click **Submit for server review** and confirm the displayed details.
8. In the terminal, type `list` and press Enter. Review payee, destination, amount,
   currency, note and expiry. Copy the full transaction ID.
9. Type `approve THE_TRANSACTION_ID`, replacing the placeholder with that ID.
10. Review the displayed fields and type `APPROVE`. This simulates operator review.
11. Within 120 seconds of submission, click **Confirm simulated payment** in the
    client. The backend atomically debits its demo balance and stores the receipt.
12. Click **Server balance / status**. Restart the lab to check balance persistence.
13. Type `quit` in the terminal to stop the server and client.

Editing fields invalidates the client's reviewed request. A replacement server
intent cancels old approvals. Restart cancels pending intents and sessions but
preserves consumed receipts and balance. There is no automatic balance reset.
For a fresh lab account after testing, close every backend process and rename the
`QuantaVoice_Data/backend_lab.sqlite3` file. Keep it if you need the receipts.

The optional lab and original seven-step GUI have different balances and keys.
Recorded voice commands do not automatically submit to this backend. The lab
lets you learn the authorization boundary before connecting verified voice evidence.

## PowerShell alternative

Open the extracted folder in File Explorer, right-click and select Open in Terminal.

```powershell
py -V:3.12 .\bootstrap_backend.py --demo-review
```

To demonstrate fail-closed behavior without simulated operator approvals:

```powershell
py -V:3.12 .\bootstrap_backend.py
```

In that mode, submissions work but approvals and completion stay blocked because
actual identity verifiers are absent. This is intentional.

To demonstrate that QNu access is unavailable rather than silently falling back:

```powershell
.\.venv-backend\Scripts\python.exe .\backend_lab.py --provider qnu
```

It must stop with “QNu is NOT integrated”.

## Implemented boundary

- Binds only to 127.0.0.1 on a randomly selected port.
- Gives the spawned client an ephemeral launch capability and key fingerprint
  through a local pipe, then issues a 30-minute session capability.
- Rejects browser-origin requests, unexpected hosts, client approval flags and
  large requests. It exposes no HTTP approval endpoint.
- Creates canonical intent data containing recipient, destination, integer paise,
  INR currency, unique ID/nonce, expiry, owner and crypto-key fingerprint.
- Uses ML-KEM-768, HKDF-SHA256, AES-256-GCM and ML-DSA-65 in the backend process.
- Checks signature, ciphertext and exact reviewed digest before an atomic SQLite
  debit plus consume. Replays, other sessions and expired requests fail.
- Persists simulated balance and receipt metadata. Keys remain in process memory.
- Rotation revokes sessions and cancels pending approvals. Restart to reconnect.

## Limits that matter

Loopback transport is HTTP, not TLS or hybrid PQC TLS. Encryption happens in the
server after the local request reaches it. Do not expose this service on a network.
The local launch capability proves access to this research process, not a customer
or institution identity. A user controlling this computer can inspect or change the
client, server, memory or SQLite file. The ledger is not tamper-proof.

The operator owns a separate console in the demo, but this is not independent
bank authorization or real biometric evidence. No actual OTP, face/KYC, QNu,
QRNG, QKD, HSM or bank payment APIs are integrated in this new mode.
Server signing establishes the lab's local intent integrity only. It does not
prove a remote bank signing identity or product certification.

Server keys and client sessions are ephemeral. Restart intentionally cancels
pending requests rather than pretending to recover signing keys from a receipt.
The SQLite ledger stores plaintext payment metadata on disk. Use demo names only.
Audit integrity, encryption at rest, managed keys, rate limiting across users,
distributed availability, backup/recovery and external review remain future work.

## Tests

The existing full test suite uses `RUN_TESTS.cmd` after original desktop setup.
The lightweight backend environment can test only this new mode:

```powershell
.\.venv-backend\Scripts\python.exe -m unittest discover -s quantavoice -p test_backend.py -v
```

No model downloads occur during backend tests. Software tests cannot establish
Windows mouse/microphone compatibility, voice accuracy or bank readiness.
