"""v17.2 step 1: real TLS and mutual TLS on the gateway and the SDK (lab PKI, real OpenSSL handshakes)."""
import json
import socket
import ssl
import tempfile
import time
import unittest, warnings
warnings.simplefilter("ignore", DeprecationWarning)
from pathlib import Path

import api_gateway as api
import gateway_bridge as gb
import sdk
from audit_log import AuditLog
from backend_store import BackendStore
from tls_dev import make_dev_pki, openssl_note


class TlsEnv(unittest.TestCase):
    mtls = False
    tls13 = False
    host = '127.0.0.1'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.d = Path(self.tmp.name)
        self.pki = make_dev_pki(self.d / 'pki')
        self.store = BackendStore(self.d / 'l.db', demo=True, provider='hybrid'); self.audit = AuditLog(self.d / 'a.jsonl')
        self.keys = api.ApiKeys(); self.key = self.keys.create('partner')
        tls = api.TlsConfig(self.pki['cert'], self.pki['key'], self.pki['ca'] if self.mtls else None, self.tls13)
        self.server, _ = api.serve(api.AuthorizationService(self.store, self.audit), self.keys,
                                   api.RateLimiter(per_second=1000, burst=1000), host=self.host, tls=tls)
        self.port = self.server.server_port
        self.url = 'https://localhost:%d' % self.port

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.store.close(); self.tmp.cleanup()

    def client(self, **kw):
        base = {'cafile': self.pki['ca'], 'retries': 0, 'timeout': 5}
        base.update(kw)
        return sdk.Client(self.url, self.key, **base)

    def pay(self, c):
        return c.create_authorization('Rahul', 'rahul@demo', '100', context={'hour': 14})


class Tls(TlsEnv):
    def test_https_request_works_with_the_lab_ca(self):
        self.assertEqual(self.pay(self.client())['status'], 'pending_review')

    def test_default_client_negotiates_tls13(self):
        ctx = ssl.create_default_context(cafile=self.pki['ca'])
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname='localhost') as t:
            self.assertEqual(t.version(), 'TLSv1.3')

    def test_untrusted_server_certificate_is_refused(self):
        c = self.client(cafile=make_dev_pki(self.d / 'other')['ca'])          # a different CA
        with self.assertRaises(Exception) as cm: self.pay(c)
        self.assertNotIsInstance(cm.exception, sdk.QuantaVoiceError)               # failed before any HTTP answer

    def test_system_trust_store_does_not_trust_the_lab_ca(self):
        with self.assertRaises(Exception): self.pay(self.client(cafile=None))

    def test_wrong_hostname_is_refused(self):
        c = sdk.Client('https://127.0.0.2:%d' % self.port, self.key, cafile=self.pki['ca'], retries=0, timeout=5)  # cert is for localhost/127.0.0.1/::1
        with self.assertRaises(Exception): self.pay(c)

    def test_plain_http_to_the_tls_port_gets_nothing(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as s:
            s.sendall(b'GET /v1/openapi.json HTTP/1.1\r\nHost: x\r\n\r\n')
            try: data = s.recv(100)
            except OSError: data = b''
        self.assertNotIn(b'HTTP/1', data)

    def test_old_tls_versions_are_refused(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1; ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            # This OpenSSL build cannot even offer TLS 1.0/1.1, so no client can negotiate them here.
            # Prove the server side forbids them as well, instead of skipping.
            cfg = api.TlsConfig(self.pki['cert'], self.pki['key'], None, False)
            self.assertGreaterEqual(cfg.context().minimum_version, ssl.TLSVersion.TLSv1_2)
            return
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as raw:
            with self.assertRaises(ssl.SSLError): ctx.wrap_socket(raw, server_hostname='localhost')

    def test_a_stalled_client_does_not_block_others(self):
        stalled = [socket.create_connection(('127.0.0.1', self.port), timeout=5) for _ in range(3)]   # connect, never handshake
        try:
            t = time.monotonic(); self.assertEqual(self.pay(self.client())['status'], 'pending_review')
            self.assertLess(time.monotonic() - t, 3)
        finally:
            for s in stalled: s.close()

    def test_garbage_does_not_kill_the_server(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as s:
            s.sendall(b'\x16\x03\x01\x00\x05garbage\r\n\r\n')
        self.assertEqual(self.pay(self.client())['status'], 'pending_review')

    def test_client_ssl_options_need_https(self):
        with self.assertRaises(ValueError): sdk.Client('http://127.0.0.1:1', self.key, cafile=self.pki['ca'])

    def test_key_files_are_private_on_posix(self):
        import os
        for k in ('key', 'client_key'):
            self.assertTrue(Path(self.pki[k]).is_file())
            # Windows has no POSIX mode bits (the ACL inherits from the user profile): check them where they exist.
            if os.name != 'nt': self.assertEqual(Path(self.pki[k]).stat().st_mode & 0o077, 0)

    def test_api_key_is_still_required_over_tls(self):
        c = sdk.Client(self.url, 'qvk_00000000.' + 'a' * 24, cafile=self.pki['ca'], retries=0)
        with self.assertRaises(sdk.QuantaVoiceError) as cm: self.pay(c)
        self.assertEqual(cm.exception.status, 401)

    def test_openssl_note_is_honest(self):
        note = openssl_note(); self.assertIn('OpenSSL', note); self.assertIn('post-quantum', note.lower())


class Tls13Only(TlsEnv):
    tls13 = True

    def test_tls12_client_is_refused_and_default_client_works(self):
        self.assertEqual(self.pay(self.client())['status'], 'pending_review')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as raw:
            with self.assertRaises(ssl.SSLError): ctx.wrap_socket(raw, server_hostname='localhost')


class MutualTls(TlsEnv):
    mtls = True

    def test_client_with_a_certificate_signed_by_the_ca_works(self):
        c = self.client(client_cert=self.pki['client_cert'], client_key=self.pki['client_key'])
        self.assertEqual(self.pay(c)['status'], 'pending_review')

    def test_client_without_a_certificate_is_refused(self):
        with self.assertRaises(Exception) as cm: self.pay(self.client())
        self.assertNotIsInstance(cm.exception, sdk.QuantaVoiceError)

    def test_client_certificate_from_another_ca_is_refused(self):
        other = make_dev_pki(self.d / 'other')
        c = self.client(client_cert=other['client_cert'], client_key=other['client_key'])
        with self.assertRaises(Exception): self.pay(c)

    def test_a_valid_certificate_does_not_replace_the_api_key(self):
        c = sdk.Client(self.url, 'qvk_00000000.' + 'a' * 24, cafile=self.pki['ca'], client_cert=self.pki['client_cert'],
                       client_key=self.pki['client_key'], retries=0)
        with self.assertRaises(sdk.QuantaVoiceError) as cm: self.pay(c)
        self.assertEqual(cm.exception.status, 401)


class NonLoopback(unittest.TestCase):
    def test_binding_beyond_loopback_requires_tls(self):
        with tempfile.TemporaryDirectory() as t:
            store = BackendStore(Path(t) / 'l.db', demo=True, provider='hybrid')
            svc = api.AuthorizationService(store, AuditLog(Path(t) / 'a.jsonl'))
            with self.assertRaises(ValueError): api.serve(svc, api.ApiKeys(), host='0.0.0.0')
            pki = make_dev_pki(Path(t) / 'pki')
            server, _ = api.serve(svc, api.ApiKeys(), host='0.0.0.0', tls=api.TlsConfig(pki['cert'], pki['key']))
            try: self.assertTrue(server.tls_enabled)
            finally: server.shutdown(); server.server_close(); store.close()


class DesktopBridge(TlsEnv):
    def test_bridge_uses_the_ca_and_client_certificate_from_the_environment(self):
        import os
        env = {'QUANTAVOICE_API_URL': self.url, 'QUANTAVOICE_API_KEY': self.key, 'QUANTAVOICE_API_CA': self.pki['ca']}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            bridge = gb.GatewayBridge.from_environment()
            self.assertTrue(bridge.consent_status()['enforced'] in (True, False))
        finally:
            for k, v in old.items():
                if v is None: os.environ.pop(k, None)
                else: os.environ[k] = v

    def test_bad_tls_configuration_is_a_clear_error_not_a_silent_fallback(self):
        import os
        old = {k: os.environ.get(k) for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY', 'QUANTAVOICE_API_CA')}
        os.environ.update({'QUANTAVOICE_API_URL': self.url, 'QUANTAVOICE_API_KEY': self.key, 'QUANTAVOICE_API_CA': '/nonexistent/ca.pem'})
        try:
            with self.assertRaises(ValueError) as cm: gb.GatewayBridge.from_environment()
            self.assertIn('TLS configuration', str(cm.exception))
        finally:
            for k, v in old.items():
                if v is None: os.environ.pop(k, None)
                else: os.environ[k] = v


if __name__ == '__main__':
    unittest.main()
