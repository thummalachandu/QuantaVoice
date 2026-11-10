"""v17.2 B8: the gateway verifies a WebAuthn assertion bound to the transaction digest."""
import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

import api_gateway as api
import challenge_phrase
import gateway_bridge as gb
import sdk
from audit_log import AuditLog
from backend_store import BackendStore
from device_gateway import DeviceVerifier, challenge_for
from fido2.utils import websafe_decode
from seven_flow import Flow
from softkey import SoftKey, make_ca

DER = serialization.Encoding.DER
STEP_UP_CTX = {'hour': 14, 'channel': 'app'}   # no device claim, no voice evidence -> the engine asks for step-up


class Env(unittest.TestCase):
    verifier_args = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); d = Path(self.tmp.name)
        self.now = [1_800_000_000.0]
        self.store = BackendStore(d / 'l.db', demo=True, provider='hybrid')
        self.audit = AuditLog(d / 'a.jsonl')
        self.devices = DeviceVerifier(clock=lambda: self.now[0], **self.verifier_args)
        self.service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService(),
                                                devices=self.devices)
        self.keys = api.ApiKeys(); self.key = self.keys.create('partner')
        self.server, _ = api.serve(self.service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
        self.url = 'http://127.0.0.1:%d' % self.server.server_port
        self.c = sdk.Client(self.url, self.key, retries=0)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.store.close(); self.tmp.cleanup()

    def register(self, key, ref='cust-1', client=None):
        c = client or self.c
        o = c.device_register_begin(ref)
        return c.device_register_complete(ref, o['session'], key('create', o['publicKey']))

    def create(self, ref='cust-1', client=None):
        return (client or self.c).create_authorization('Rahul', 'rahul@demo', '100', customer_ref=ref, context=STEP_UP_CTX)

    def code(self, fn, *a, **k):
        with self.assertRaises(sdk.QuantaVoiceError) as cm: fn(*a, **k)
        return cm.exception.status, cm.exception.code


class Assertion(Env):
    def test_verified_device_satisfies_step_up_and_payment_completes(self):
        key = SoftKey(); self.assertEqual(self.register(key)['attestation'], 'unattested')
        r = self.create(); self.assertTrue(r['step_up_required'])
        o = self.c.device_assertion_begin(r['id'])
        out = self.c.device_assertion_complete(r['id'], o['session'], key('get', o['publicKey']))
        self.assertTrue(out['verified'])
        st = self.c.get_authorization(r['id'])
        self.assertTrue(st['device_verified']); self.assertFalse(st['step_up_required'])
        self.store.approve_from_console(r['id'])
        self.assertEqual(self.c.confirm_authorization(r['id'], r['digest'])['status'], 'consumed')

    def test_challenge_commits_to_the_digest(self):
        key = SoftKey(); self.register(key); r = self.create()
        o = self.c.device_assertion_begin(r['id'])
        self.assertEqual(o['digest'], r['digest'])
        self.assertEqual(websafe_decode(o['publicKey']['challenge']), challenge_for(r['digest'], bytes.fromhex(o['nonce'])))

    def test_no_device_no_step_up_relief(self):
        r = self.create()
        self.assertEqual(self.code(self.c.device_assertion_begin, r['id']), (404, 'no_device'))
        self.assertEqual(self.code(self.c.confirm_authorization, r['id'], r['digest'])[1], 'step_up_required')

    def test_signature_over_another_challenge_fails(self):
        key = SoftKey(); self.register(key)
        r1, r2 = self.create(), self.create()
        o1 = self.c.device_assertion_begin(r1['id']); o2 = self.c.device_assertion_begin(r2['id'])
        stale = key('get', o2['publicKey'])                         # signed for payment 2
        self.assertEqual(self.code(self.c.device_assertion_complete, r1['id'], o1['session'], stale)[1], 'device_verification_failed')
        self.assertTrue(self.c.get_authorization(r1['id'])['step_up_required'])

    def test_session_is_single_use_even_after_failure(self):
        key = SoftKey(); self.register(key); r = self.create(); o = self.c.device_assertion_begin(r['id'])
        bad = key('get', o['publicKey'], challenge='AAAA')
        self.assertEqual(self.code(self.c.device_assertion_complete, r['id'], o['session'], bad)[1], 'device_verification_failed')
        good = key('get', o['publicKey'])
        self.assertEqual(self.code(self.c.device_assertion_complete, r['id'], o['session'], good)[1], 'invalid_session')

    def test_session_expires(self):
        key = SoftKey(); self.register(key); r = self.create(); o = self.c.device_assertion_begin(r['id'])
        self.now[0] += 121
        self.assertEqual(self.code(self.c.device_assertion_complete, r['id'], o['session'], key('get', o['publicKey']))[1], 'invalid_session')

    def test_session_cannot_be_used_on_another_authorization(self):
        key = SoftKey(); self.register(key); r1, r2 = self.create(), self.create()
        o = self.c.device_assertion_begin(r1['id'])
        self.assertEqual(self.code(self.c.device_assertion_complete, r2['id'], o['session'], key('get', o['publicKey']))[1], 'invalid_session')

    def test_cloned_authenticator_counter_is_rejected(self):
        key = SoftKey(); self.register(key)
        r = self.create(); o = self.c.device_assertion_begin(r['id'])
        self.c.device_assertion_complete(r['id'], o['session'], key('get', o['publicKey']))
        r2 = self.create(); o2 = self.c.device_assertion_begin(r2['id'])
        self.assertEqual(self.code(self.c.device_assertion_complete, r2['id'], o2['session'], key('get', o2['publicKey'], counter=1))[1],
                         'device_verification_failed')

    def test_user_verification_is_required(self):
        key = SoftKey(user_verified=False); o = self.c.device_register_begin('cust-1')
        self.assertEqual(self.code(self.c.device_register_complete, 'cust-1', o['session'], key('create', o['publicKey']))[1],
                         'device_verification_failed')

    def test_wrong_origin_and_wrong_rp_are_rejected(self):
        for kw in ({'origin': 'https://evil.example'}, {'rp_id': 'evil.example'}):
            o = self.c.device_register_begin('cust-1')
            self.assertEqual(self.code(self.c.device_register_complete, 'cust-1', o['session'], SoftKey(**kw)('create', o['publicKey']))[1],
                             'device_verification_failed')

    def test_a_device_belongs_to_its_customer_and_api_key(self):
        key = SoftKey(); self.register(key)
        r = self.create(ref='someone-else')
        self.assertEqual(self.code(self.c.device_assertion_begin, r['id']), (404, 'no_device'))
        other = sdk.Client(self.url, self.keys.create('other'), retries=0)
        r3 = self.create(client=other)
        self.assertEqual(self.code(other.device_assertion_begin, r3['id']), (404, 'no_device'))

    def test_authorization_without_customer_ref_cannot_use_device(self):
        r = self.c.create_authorization('Rahul', 'rahul@demo', '100', context=STEP_UP_CTX)
        self.assertEqual(self.code(self.c.device_assertion_begin, r['id']), (400, 'customer_ref_required'))

    def test_credential_cannot_be_registered_twice_and_device_count_is_capped(self):
        key = SoftKey(); self.register(key)
        self.assertEqual(self.code(self.register, key, 'cust-2')[1], 'device_exists')
        for _ in range(4): self.register(SoftKey())
        self.assertEqual(self.code(self.c.device_register_begin, 'cust-1'), (409, 'too_many_devices'))

    def test_audit_has_events_but_not_the_customer_reference(self):
        key = SoftKey(); self.register(key, 'cust-secret-42'); r = self.create('cust-secret-42')
        o = self.c.device_assertion_begin(r['id']); self.c.device_assertion_complete(r['id'], o['session'], key('get', o['publicKey']))
        text = self.audit.path.read_text(encoding='utf-8')
        for ev in ('device.registered', 'device.challenge_issued', 'device.assertion_verified'): self.assertIn(ev, text)
        self.assertNotIn('cust-secret-42', text)

    def test_scope_for_registration(self):
        weak = sdk.Client(self.url, self.keys.create('w', scopes=('authorizations:write',)), retries=0)
        self.assertEqual(self.code(weak.device_register_begin, 'cust-1'), (403, 'insufficient_scope'))


class NotConfigured(unittest.TestCase):
    def test_501_without_devices(self):
        with tempfile.TemporaryDirectory() as t:
            store = BackendStore(Path(t) / 'l.db', demo=True, provider='hybrid'); audit = AuditLog(Path(t) / 'a.jsonl')
            keys = api.ApiKeys(); key = keys.create('p')
            server, _ = api.serve(api.AuthorizationService(store, audit), keys, api.RateLimiter(per_second=1000, burst=1000))
            try:
                c = sdk.Client('http://127.0.0.1:%d' % server.server_port, key, retries=0)
                with self.assertRaises(sdk.QuantaVoiceError) as cm: c.device_register_begin('c1')
                self.assertEqual(cm.exception.status, 501)
            finally:
                server.shutdown(); server.server_close(); store.close()


class Attestation(Env):
    ca = make_ca()
    verifier_args = {'trust_roots': [ca[1].public_bytes(DER)]}

    def test_certificate_attestation_from_a_trusted_root_is_accepted(self):
        out = self.register(SoftKey(fmt='packed-x5c', ca=self.ca)); self.assertEqual(out['attestation'], 'attested')

    def test_none_and_self_attestation_are_not_trusted_when_roots_are_configured(self):
        for fmt in ('none', 'packed-self'):
            o = self.c.device_register_begin('cust-1')
            self.assertEqual(self.code(self.c.device_register_complete, 'cust-1', o['session'], SoftKey(fmt=fmt)('create', o['publicKey']))[1],
                             'attestation_untrusted' if fmt != 'none' else 'attestation_untrusted')

    def test_untrusted_root_is_rejected(self):
        o = self.c.device_register_begin('cust-1')
        k = SoftKey(fmt='packed-x5c', ca=make_ca('Other Root'))
        self.assertEqual(self.code(self.c.device_register_complete, 'cust-1', o['session'], k('create', o['publicKey']))[1], 'attestation_untrusted')

    def test_expired_attestation_certificate_is_rejected(self):
        o = self.c.device_register_begin('cust-1')
        k = SoftKey(fmt='packed-x5c', ca=self.ca, leaf_days=10, leaf_start=-400)
        self.assertEqual(self.code(self.c.device_register_complete, 'cust-1', o['session'], k('create', o['publicKey']))[1], 'attestation_untrusted')

    def test_attested_device_assertion_reports_level(self):
        key = SoftKey(fmt='packed-x5c', ca=self.ca); self.register(key); r = self.create()
        o = self.c.device_assertion_begin(r['id'])
        self.assertEqual(self.c.device_assertion_complete(r['id'], o['session'], key('get', o['publicKey']))['attestation'], 'attested')


class RequireAttested(unittest.TestCase):
    def test_require_attested_needs_roots(self):
        with self.assertRaises(ValueError): DeviceVerifier(require_attested=True)


class DesktopFlow(Env):
    def flow(self):
        f = Flow(gateway=gb.GatewayBridge(self.url, self.key, customer_ref='cust-1'))
        f.start('Rahul', '100', 'demo-rahul', 'lunch')
        f.scenario(0, True); f.verify_pin('246810'); f.issue_otp(); f.verify_otp(f.otp)
        for s in (3, 4, 5, 6): f.scenario(s, True)
        return f

    def test_desktop_registers_then_device_verifies_instead_of_the_spoken_challenge(self):
        f = self.flow(); key = SoftKey()
        self.assertTrue(f.api_device_register(key)['registered'])
        f.api_submit(hour=14); self.assertTrue(f.api['step_up'])
        f.api_device_verify(key)
        self.assertTrue(f.api['challenge_ok']); self.assertTrue(f.api['device_ok'])
        self.store.approve_from_console(f.api['id']); f.api_confirm(); self.assertEqual(f.stage, 8)

    def test_desktop_refuses_a_challenge_that_does_not_commit_to_what_was_reviewed(self):
        f = self.flow(); key = SoftKey(); f.api_device_register(key); f.api_submit(hour=14)
        real = f.gateway.device_assertion_begin
        def forged(auth_id):
            o = real(auth_id); o['nonce'] = '00' * 16; return o       # challenge no longer matches digest+nonce
        f.gateway.device_assertion_begin = forged
        with self.assertRaises(ValueError): f.api_device_verify(key)
        self.assertTrue(f.blocked)

    def test_a_failed_device_does_not_satisfy_step_up(self):
        f = self.flow(); good = SoftKey(); f.api_device_register(good); f.api_submit(hour=14)
        with self.assertRaises(ValueError): f.api_device_verify(SoftKey())   # unregistered device
        self.assertFalse(f.api['challenge_ok'])
        with self.assertRaises(ValueError): f.api_confirm()


# ---- GUI (needs a display) ----
try:
    from test_v17_gui import GuiBase, texts
except Exception:  # pragma: no cover
    GuiBase = None

if GuiBase is not None:
    import json, os
    from unittest import mock

    class GuiDevice(GuiBase):
        def setUp(self):
            super().setUp()
            if self.root is None: return
            self.tmp = tempfile.TemporaryDirectory(); d = Path(self.tmp.name)
            self.store = BackendStore(d / 'l.db', demo=True, provider='hybrid'); self.audit = AuditLog(d / 'a.jsonl')
            service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService(),
                                               devices=DeviceVerifier())
            self.keys = api.ApiKeys(); key = self.keys.create('gui')
            self.server, _ = api.serve(service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
            os.environ['QUANTAVOICE_API_URL'] = 'http://127.0.0.1:%d' % self.server.server_port
            os.environ['QUANTAVOICE_API_KEY'] = key
            self.app = self.ResearchVoice(self.root); self.app.presentation.set(True)

        def tearDown(self):
            for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
            if getattr(self, 'server', None):
                self.server.shutdown(); self.server.server_close(); self.store.close(); self.tmp.cleanup()
            super().tearDown()

        def test_register_then_verify_buttons_use_the_gateway(self):
            soft = SoftKey()
            with mock.patch('research_ui.gateway_authenticator', lambda origin: soft):
                f = self.app.flow; f.start('Rahul', '100', 'demo-rahul')
                f.scenario(0, True); f.verify_pin('246810'); f.issue_otp(); f.verify_otp(f.otp)
                for s in (3, 4, 5, 6): f.scenario(s, True)
                self.app.render()
                self.assertIn('Register this device with the gateway', ' | '.join(texts(self.app.panel)))
                self.app.device_register_clicked(); self.pump()
                self.app.api_submit_clicked(); self.pump()
                self.assertIn('Verify with my device (WebAuthn, checked by the gateway)', ' | '.join(texts(self.app.panel)))
                self.app.device_verify_clicked(); self.pump()
                self.assertTrue(f.api['challenge_ok'] and f.api['device_ok'])


if __name__ == '__main__':
    unittest.main()
