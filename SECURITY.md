# Security Policy and Notes: QuantaVoice v17.3

## 1. What this project is (and is not)

QuantaVoice is a **lab and demo** of a voice-authorised payment flow. Simulated funds and simulated identity gates
are used throughout. It has **not** been independently audited and must **not** be used to move real money, protect
real bank accounts, or hold real customer data.

Real code in the project: scrypt PIN verification with a lockout, a one-time code check, ML-KEM-768 + AES-256-GCM +
ML-DSA-65 payment envelope, hashed and revocable API keys, HMAC-signed webhooks, and a development TLS PKI.
Simulated: voice and anti-spoofing, face and liveness, fingerprint / FIDO2 gate, agent review, and video KYC.

## 2. What no code can promise

- No system is "unhackable". Security comes from layers: access control, encryption, least privilege, patching,
  monitoring, and independent review.
- A **public** GitHub repository can be read by anyone. Source code is never a secret by itself. Protection comes
  from keeping secrets, keys and personal data **out of the repository**, and from restricting who can read and
  write the repository.
- Anyone who can read a compiled or shipped copy of the app can read its code. Do not rely on hidden code as security.

## 3. Repository rules (apply to every file)

1. **Make the repository private** (GitHub → Settings → General → Danger Zone → Change visibility). Use a public
   repository only for code you are happy for anyone to read.
2. **Turn on two-factor authentication** on the GitHub account, and use hardware keys or passkeys where possible.
3. **Never commit secrets**: API keys, passwords, PINs, private keys, `.pem` / `.key` files, tokens, `.env` files,
   contact lists, device credentials, or provider vaults. The included `.gitignore` blocks the common ones.
4. **Enable GitHub secret scanning and push protection** (Settings → Code security).
5. **Protect the main branch**: require pull requests and at least one review before merging.
6. **Sign commits** (SSH or GPG) so you can prove who made a change.
7. **Pin dependencies** (`requirements.txt` already pins exact versions) and review updates before installing them.
8. **Scan dependencies** regularly, for example with `pip-audit` or GitHub Dependabot alerts.
9. **If a secret is ever committed**, treat it as leaked: revoke or rotate it immediately. Deleting it in a later commit
   is not enough, because the old commit stays in history.

## 4. Protecting files on your own computer

- Keep the project in an encrypted disk or folder (BitLocker on Windows, FileVault on macOS, LUKS on Linux).
- Use a strong passphrase on any vault or key file. The provider vault already requires at least 12 characters and
  encrypts with scrypt + AES-256-GCM.
- Store keys in an operating-system keystore or a hardware token, not in the project folder.

## 5. Running the app safely

- The live demo binds to **127.0.0.1 only** and rejects requests with a foreign `Host` header, cross-site POSTs,
  bodies over 1 KB, and unknown scenario names. Do not change it to bind to `0.0.0.0`.
- The demo PIN (`246810`) is public by design, is shown in the UI and source, and is not a credential.
- The development certificates and CA are for the lab only. Do not use them in production.

## 6. Known weaknesses (honest list)

| # | Area | Issue | Risk level | Planned fix |
|---|---|---|---|---|
| 1 | Live demo CSP | `script-src 'unsafe-inline'` allows inline scripts. A content-security policy with nonces or hashes would be stronger. | Low (loopback, demo page) | Move script to a separate file and use `script-src 'self'` |
| 2 | Local stores | Contacts, device credentials and some JSON state are plain files. Default file permissions are used, not `0600`. | Medium on shared machines | Set `0600` on write, or encrypt at rest |
| 3 | No `.gitignore` before this change | Runtime files and caches could have been committed. | High if pushed as-is | Added `.gitignore` |
| 4 | Simulated gates | Voice, face, fingerprint and KYC checks are simulated and always accept the legitimate path. | Expected for the demo; disqualifying for production | Replace with reviewed, certified providers |
| 5 | Post-quantum claims | Some wording implies post-quantum protection end to end. TLS hybrid groups are only noted, not verified. | Medium (misleading) | Verify negotiated group in tests before claiming it |
| 6 | Earlier demo page | The old standalone page showed made-up accuracy figures. The v17.3 page replaced them, but old copies may still exist. | Low (misleading) | Delete old copies |
| 7 | No independent audit | Nothing here has been reviewed by an external security firm. | High before any real use | Commission a security audit and penetration test |

## 7. Reporting a vulnerability

Do not open a public issue for a security problem. Contact the maintainer privately with:
- what you found,
- the steps to reproduce it,
- the version (`v17.3`) and your operating system.

Please allow reasonable time for a fix before public disclosure.
