"""QuantaVoice v16 API lab: REST gateway + operator console. SIMULATED funds, loopback only."""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'quantavoice'))
import api_gateway as api
from audit_log import AuditLog
from backend_store import BackendStore
from challenge_phrase import ChallengeService
from privacy_consent import ConsentLedger, TemplateVault


def main():
    p = argparse.ArgumentParser(description='Local REST API lab, no real money or biometric verification.')
    p.add_argument('--demo-review', action='store_true', help='Allow explicitly simulated console approval')
    p.add_argument('--provider', choices=['local', 'hybrid'], default='hybrid')
    p.add_argument('--port', type=int, default=8787)
    p.add_argument('--no-consent', action='store_true', help='Do not enforce biometric consent (v17 behaviour)')
    p.add_argument('--dev-tls', action='store_true', help='Serve HTTPS with a freshly generated lab CA (writes QuantaVoice_Data/tls)')
    p.add_argument('--mtls', action='store_true', help='With --dev-tls: also require a client certificate')
    p.add_argument('--tls-cert'); p.add_argument('--tls-key'); p.add_argument('--tls-client-ca', help='Require client certificates signed by this CA (mutual TLS)')
    p.add_argument('--tls13-only', action='store_true')
    p.add_argument('--host', default='127.0.0.1', help='Only with TLS can this be anything but loopback')
    p.add_argument('--webauthn-origin', default='https://localhost', help='Origin the customer device signs for (WebAuthn)')
    p.add_argument('--webauthn-rp-id', default='localhost')
    p.add_argument('--attestation-root', action='append', default=[], help='PEM root that device attestation must chain to (repeatable)')
    p.add_argument('--require-attested', action='store_true')
    p.add_argument('--webhook', help='Webhook URL (https, public host)')
    p.add_argument('--webhook-secret', help='At least 16 characters')
    args = p.parse_args()
    data = ROOT / 'QuantaVoice_Data'
    stamp = time.strftime('%Y%m%d_%H%M%S')
    audit = AuditLog(data / ('audit_%s.jsonl' % stamp))
    (data / ('audit_%s.pub' % stamp)).write_bytes(audit.public)  # needed to verify the log later
    store = BackendStore(data / 'backend_lab.sqlite3', demo=args.demo_review, provider=args.provider)
    dispatcher = api.WebhookDispatcher()
    if args.webhook:
        dispatcher.register(args.webhook, args.webhook_secret or '')
    ledger = vault = None
    if not args.no_consent:
        # Persist consent across restarts only if you supply a key. Otherwise pseudonyms change and consent resets.
        hexkey = os.environ.get('QUANTAVOICE_CONSENT_KEY', '')
        master = bytes.fromhex(hexkey) if len(hexkey) == 64 else None
        ledger = ConsentLedger(data / 'consent.sqlite3', master_key=master)
        vault = TemplateVault(data / 'templates.sqlite3', ledger)
        print('Biometric consent: ENFORCED%s' % ('' if master else ' (no QUANTAVOICE_CONSENT_KEY: consent resets on restart)'), flush=True)
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import serialization as _ser
    from device_gateway import DeviceVerifier
    roots = [_x509.load_pem_x509_certificate(Path(f).read_bytes()).public_bytes(_ser.Encoding.DER) for f in args.attestation_root]
    devices = DeviceVerifier(rp_id=args.webauthn_rp_id, origins=(args.webauthn_origin,), trust_roots=roots, require_attested=args.require_attested)
    print('Device verification: WebAuthn, origin %s, attestation %s' % (args.webauthn_origin,
          'REQUIRED, %d trust root(s)' % len(roots) if args.require_attested else ('checked against %d root(s)' % len(roots) if roots else 'not checked (no roots)')), flush=True)
    service = api.AuthorizationService(store, audit, challenges=ChallengeService(), dispatcher=dispatcher,
                                       consent=ledger, vault=vault, devices=devices)
    keys = api.ApiKeys()
    tls = None
    if args.dev_tls or args.tls_cert:
        if args.dev_tls:
            from tls_dev import make_dev_pki, openssl_note
            pki = make_dev_pki(data / 'tls')
            tls = api.TlsConfig(pki['cert'], pki['key'], pki['ca'] if args.mtls else None, args.tls13_only)
            print('Lab TLS files in %s (LAB ONLY, not a production CA)' % (data / 'tls'), flush=True)
            print('Client environment: QUANTAVOICE_API_CA=%s' % pki['ca'] + (' QUANTAVOICE_API_CLIENT_CERT=%s QUANTAVOICE_API_CLIENT_KEY=%s' % (pki['client_cert'], pki['client_key']) if args.mtls else ''), flush=True)
        else:
            tls = api.TlsConfig(args.tls_cert, args.tls_key, args.tls_client_ca, args.tls13_only)
    server, _ = api.serve(service, keys, api.RateLimiter(), host=args.host, port=args.port, tls=tls)
    scheme = 'https' if tls else 'http'
    if tls:
        from tls_dev import openssl_note
        print('QUANTAVOICE API LAB: SIMULATED FUNDS ONLY, HTTPS%s' % (' with mutual TLS' if tls.client_ca else ''), flush=True)
        print('TLS library: %s' % openssl_note(), flush=True)
    else:
        print('QUANTAVOICE API LAB: SIMULATED FUNDS ONLY, loopback HTTP, no TLS', flush=True)
    print('Base URL: %s://%s:%d   OpenAPI: /v1/openapi.json' % (scheme, 'localhost' if tls else '127.0.0.1', server.server_port), flush=True)
    print('Audit log: %s' % (data / ('audit_%s.jsonl' % stamp)), flush=True)
    print('Crypto provider: %s' % store.crypto.name, flush=True)
    print('Commands: newkey NAME, list, approve ID, verify, quit', flush=True)
    try:
        while True:
            try:
                cmd = input('Operator> ').strip().split()
            except (EOFError, KeyboardInterrupt):
                break
            try:
                if not cmd:
                    continue
                if cmd == ['quit']:
                    break
                elif cmd[0] == 'newkey' and len(cmd) == 2:
                    print('API key (shown once):', keys.create(cmd[1]))
                elif cmd == ['list']:
                    for i in store.pending():
                        print(json.dumps(i, ensure_ascii=False, indent=2))
                elif cmd[0] == 'approve' and len(cmd) == 2:
                    match = [x for x in store.pending() if x['id'] == cmd[1]]
                    if not match:
                        raise ValueError('Unknown or expired pending ID.')
                    print(json.dumps(match[0], ensure_ascii=False, indent=2))
                    if input('Type APPROVE for a simulated operator review: ').strip() != 'APPROVE':
                        print('No approval.'); continue
                    store.approve_from_console(cmd[1])
                    audit.append('operator.approved_simulated', {'id': cmd[1]})
                    print('SIMULATED review approved.')
                elif cmd == ['verify']:
                    print('Audit chain:', audit.verify())
                else:
                    print('Use newkey NAME, list, approve ID, verify or quit.')
            except Exception as exc:
                print('Blocked:', str(exc))
    finally:
        print('Final audit verification:', audit.verify(), flush=True)
        server.shutdown(); server.server_close(); store.close()


if __name__ == '__main__':
    main()
