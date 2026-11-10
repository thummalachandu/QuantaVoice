import socket
import tempfile
import unittest
from pathlib import Path

import api_gateway as api
import challenge_phrase
import gateway_bridge as gb
from audit_log import AuditLog
from backend_store import BackendStore
from seven_flow import Flow

CFG = {'asv_threshold': 0.4, 'cm_threshold': 1.5, 'thresholds_from_dev': True}
GOOD = {'asv': 0.8, 'cm': 4.0, 'asv_ms': 5.0, 'cm_ms': 5.0}
BAD = {'asv': 0.1, 'cm': -6.0, 'asv_ms': 5.0, 'cm_ms': 5.0}


def to_stage7(flow, voice=None, device=False):
    flow.start('Rahul', '100', 'demo-rahul', 'lunch')
    if voice is not None:
        flow.record_voice_evidence(voice, CFG)
    flow.scenario(0, True)
    flow.verify_pin('246810')
    flow.issue_otp(); flow.verify_otp(flow.otp)
    flow.scenario(3, True)
    if device:
        flow.record_device_verified()
    flow.scenario(4, True)
    flow.scenario(5, True); flow.scenario(6, True)
    assert flow.stage == 7


class Spy:
    """Wraps a real bridge and records exactly what the desktop sends."""
    def __init__(self, real): self.real, self.contexts, self.calls = real, [], []
    def create(self, recipient, destination, amount, note, context, key):
        self.contexts.append(dict(context)); self.calls.append(('create', key))
        return self.real.create(recipient, destination, amount, note, context, key)
    def __getattr__(self, name): return getattr(self.real, name)


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = BackendStore(Path(self.tmp.name) / 'l.db', demo=True, provider='hybrid')
        self.audit = AuditLog(Path(self.tmp.name) / 'a.jsonl')
        self.service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService())
        self.keys = api.ApiKeys(); key = self.keys.create('desktop')
        self.server, _ = api.serve(self.service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
        self.url = 'http://127.0.0.1:%d' % self.server.server_port
        self.bridge = gb.GatewayBridge(self.url, key)
        self.spy = Spy(self.bridge)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.store.close(); self.tmp.cleanup()

    def count(self):
        return self.store.db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]


class V16Compatibility(unittest.TestCase):
    def test_without_gateway_local_path_is_unchanged(self):
        f = Flow(); to_stage7(f)
        f.encrypt(); out = f.confirm()
        self.assertEqual(f.stage, 8); self.assertIn('id', out)

    def test_gateway_mode_disables_local_payment(self):
        f = Flow(gateway=object()); to_stage7(f)
        for fn in (f.encrypt, f.confirm, f.tamper):
            with self.assertRaises(ValueError): fn()
        self.assertEqual(f.stage, 7)


class ApiFlow(Env):
    def test_presentation_scenarios_never_become_evidence(self):
        f = Flow(gateway=self.spy); to_stage7(f)
        self.assertIsNone(f.voice_evidence); self.assertFalse(f.device_verified)
        f.api_submit(hour=14)
        ctx = self.spy.contexts[0]
        self.assertEqual(set(ctx), {'channel', 'hour'})  # no scores, no device claim
        self.assertTrue(f.api['step_up'])  # the engine demands step-up for missing evidence
        self.assertIn('asv_score', f.api['risk']['missing_evidence'])

    def test_real_evidence_reaches_api_and_challenge_is_never_claimed(self):
        f = Flow(gateway=self.spy); to_stage7(f, voice=GOOD, device=True)
        f.api_submit(hour=14)
        ctx = self.spy.contexts[0]
        self.assertEqual(set(ctx), {'channel', 'hour', 'asv_score', 'cm_score', 'device_bound'})
        self.assertGreater(ctx['asv_score'], 0.5); self.assertGreater(ctx['cm_score'], 0.5)
        self.assertNotIn('challenge_verified', ctx)

    def test_full_payment_with_real_evidence(self):
        f = Flow(gateway=self.spy); to_stage7(f, voice=GOOD, device=True)
        f.api_submit(hour=14)
        # Engine needs the spoken challenge to be established by the API, never by the client.
        if f.api['step_up']:
            spoken, _ = f.api_challenge('en'); self.assertTrue(f.api_verify_challenge(spoken))
        self.assertEqual(f.api_status(), 'pending')
        with self.assertRaises(ValueError): f.api_confirm()  # operator has not approved
        self.assertEqual(f.stage, 7)
        self.store.approve_from_console(f.api['id'])
        self.assertEqual(f.api_status(), 'approved')
        out = f.api_confirm()
        self.assertEqual((f.stage, out['status']), (8, 'consumed'))
        self.assertEqual(self.store.db.execute('SELECT status FROM transactions').fetchone()[0], 'consumed')
        balance = lambda: self.store.db.execute('SELECT balance FROM account WHERE id=1').fetchone()[0]
        self.assertEqual(balance(), 5000000 - 10000)  # exactly INR 100 left the simulated account, once

    def test_step_up_blocks_confirmation_until_api_verifies_challenge(self):
        f = Flow(gateway=self.spy); to_stage7(f); f.api_submit(hour=14)
        self.store.approve_from_console(f.api['id'])
        with self.assertRaises(ValueError) as ctx: f.api_confirm()
        self.assertIn('challenge', str(ctx.exception))
        spoken, _ = f.api_challenge('es')
        self.assertFalse(f.api_verify_challenge('uno dos tres'))  # wrong digits: attempt consumed
        with self.assertRaises(ValueError): f.api_verify_challenge('anything')  # needs a fresh challenge
        spoken, _ = f.api_challenge('de'); self.assertTrue(f.api_verify_challenge(spoken))
        self.assertEqual(f.api_confirm()['status'], 'consumed')

    def test_spoof_evidence_is_declined_and_nothing_is_created(self):
        f = Flow(gateway=self.spy); to_stage7(f, voice=BAD)
        with self.assertRaises(ValueError) as ctx: f.api_submit(hour=14)
        self.assertIn('declined', str(ctx.exception).lower())
        self.assertTrue(f.blocked); self.assertEqual(self.count(), 0)
        self.assertEqual(self.store.db.execute('SELECT balance FROM account WHERE id=1').fetchone()[0], 5000000)

    def test_submit_twice_is_refused(self):
        f = Flow(gateway=self.spy); to_stage7(f); f.api_submit(hour=14)
        with self.assertRaises(ValueError): f.api_submit(hour=14)
        self.assertEqual(self.count(), 1)

    def test_evidence_recording_is_stage_locked(self):
        f = Flow(gateway=self.spy); f.start('Rahul', '100', 'demo-rahul')
        with self.assertRaises(ValueError): f.record_device_verified()  # still at stage 0
        f.scenario(0, True)
        with self.assertRaises(ValueError): f.record_voice_evidence(GOOD, CFG)
        with self.assertRaises(ValueError): Flow(gateway=self.spy).record_voice_evidence({'asv': .9, 'cm': 3}, CFG)

    def test_new_payment_resets_evidence(self):
        f = Flow(gateway=self.spy); to_stage7(f, voice=GOOD, device=True); f.api_submit(hour=14)
        f.start('Rahul', '5', 'demo-rahul')
        self.assertIsNone(f.voice_evidence); self.assertFalse(f.device_verified); self.assertIsNone(f.api)

    def test_needs_saved_recipient(self):
        f = Flow(gateway=self.spy); f.start('Rahul', '100'); 
        f.scenario(0, True); f.verify_pin('246810'); f.issue_otp(); f.verify_otp(f.otp)
        for s in (3, 4, 5, 6): f.scenario(s, True)
        with self.assertRaises(ValueError): f.api_submit(hour=14)


class FailClosed(Env):
    def test_outage_never_falls_back_to_local_payment(self):
        s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
        down = gb.GatewayBridge('http://127.0.0.1:%d' % port, 'qvk_aaaaaaaa.' + 'x' * 30, timeout=1)
        f = Flow(gateway=down); to_stage7(f); before = f.lab.balance
        with self.assertRaises(ValueError) as ctx: f.api_submit(hour=14)
        self.assertIn('no local fallback', str(ctx.exception).lower())
        self.assertEqual((f.stage, f.blocked, f.lab.balance), (7, False, before))
        with self.assertRaises(ValueError): f.confirm()

    def test_broken_configuration_blocks(self):
        f = Flow(gateway=gb.GatewayBridge.broken('bad key')); to_stage7(f)
        with self.assertRaises(ValueError) as ctx: f.api_submit(hour=14)
        self.assertIn('unusable', str(ctx.exception)); self.assertEqual(f.stage, 7)

    def test_retry_after_lost_response_replays_not_duplicates(self):
        flaky = Spy(self.bridge); real_create = flaky.real.create; seen = []
        def create(*a):
            r = real_create(*a); seen.append(a[-1])
            if len(seen) == 1: raise gb.GatewayUnavailable('response lost')
            return r
        flaky.real = type('R', (), {'create': staticmethod(create), '__getattr__': lambda s, n: getattr(self.bridge, n)})()
        f = Flow(gateway=flaky); to_stage7(f)
        with self.assertRaises(ValueError): f.api_submit(hour=14)
        f.api_submit(hour=14)
        self.assertEqual(seen[0], seen[1]); self.assertEqual(self.count(), 1)

    def test_rejected_by_api_is_reported(self):
        revoked = gb.GatewayBridge(self.url, 'qvk_aaaaaaaa.' + 'y' * 30)
        f = Flow(gateway=revoked); to_stage7(f)
        with self.assertRaises(ValueError) as ctx: f.api_submit(hour=14)
        self.assertIn('invalid_api_key', str(ctx.exception))


class Tampered(Env):
    def run_with(self, mutate):
        class Evil(Spy):
            def create(s, *a):
                r = dict(self.bridge.create(*a)); mutate(r); return r
        f = Flow(gateway=Evil(self.bridge)); to_stage7(f)
        with self.assertRaises(ValueError): f.api_submit(hour=14)
        self.assertTrue(f.blocked); self.assertEqual(f.stage, 7)

    def test_amount_mismatch_blocks(self): self.run_with(lambda r: r.update(amount_paise=r['amount_paise'] + 1))
    def test_recipient_mismatch_blocks(self): self.run_with(lambda r: r.update(recipient='Mallory'))
    def test_destination_mismatch_blocks(self): self.run_with(lambda r: r.update(destination='mallory@demo'))
    def test_currency_mismatch_blocks(self): self.run_with(lambda r: r.update(currency='USD'))

    def test_digest_change_detected_at_status(self):
        f = Flow(gateway=self.bridge); to_stage7(f); f.api_submit(hour=14)
        f.api['digest'] = '0' * 64
        with self.assertRaises(ValueError): f.api_status()
        self.assertTrue(f.blocked)

    def test_reject_at_stage_seven_is_safe(self):
        f = Flow(gateway=self.bridge); to_stage7(f)
        with self.assertRaises(ValueError): f.reject('test')
        self.assertTrue(f.blocked)


class BridgeConfig(unittest.TestCase):
    def test_not_configured_returns_none(self):
        import os
        for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
        self.assertIsNone(gb.GatewayBridge.from_environment(Path(tempfile.mkdtemp()) / 'none.json'))

    def test_file_config_and_validation(self):
        import json, os
        for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
        d = Path(tempfile.mkdtemp()); p = d / 'g.json'
        p.write_text(json.dumps({'base_url': 'http://127.0.0.1:1', 'api_key': 'qvk_deadbeef.' + 'a' * 30}))
        self.assertIsNotNone(gb.GatewayBridge.from_environment(p))
        p.write_text(json.dumps({'base_url': 'http://127.0.0.1:1', 'api_key': 'nope'}))
        with self.assertRaises(ValueError): gb.GatewayBridge.from_environment(p)
        p.write_text('{not json')
        with self.assertRaises(ValueError): gb.GatewayBridge.from_environment(p)
        p.write_text(json.dumps({'base_url': 'http://evil.example.com', 'api_key': 'qvk_deadbeef.' + 'a' * 30}))
        with self.assertRaises(ValueError): gb.GatewayBridge.from_environment(p)

    def test_destination_must_be_demo(self):
        b = gb.GatewayBridge('http://127.0.0.1:1', 'qvk_deadbeef.' + 'a' * 30)
        with self.assertRaises(ValueError): b.create('A', 'a@okbank', '1', '', {}, 'k' * 10)


if __name__ == '__main__':
    unittest.main()
