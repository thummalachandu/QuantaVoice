"""v17.1 B6: privacy consent wired into the API, SDK, desktop flow and GUI."""
import json
import tempfile
import unittest
from pathlib import Path

import api_gateway as api
import challenge_phrase
import gateway_bridge as gb
import sdk
from audit_log import AuditLog
from backend_store import BackendStore
from privacy_consent import ConsentLedger, TemplateVault
from seven_flow import Flow

CFG = {'asv_threshold': 0.4, 'cm_threshold': 1.5, 'thresholds_from_dev': True}
GOOD = {'asv': 0.8, 'cm': 4.0, 'asv_ms': 5.0, 'cm_ms': 5.0}
BOTH = {'asv_score': 0.9, 'cm_score': 0.9}


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


class Env(unittest.TestCase):
    enforce = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); d = Path(self.tmp.name)
        self.clock = Clock()
        self.store = BackendStore(d / 'l.db', demo=True, provider='hybrid')
        self.audit = AuditLog(d / 'a.jsonl')
        self.ledger = self.vault = None
        if self.enforce:
            self.ledger = ConsentLedger(d / 'c.db', master_key=b'k' * 32, clock=self.clock)
            self.vault = TemplateVault(d / 't.db', self.ledger, clock=self.clock)
        self.service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService(),
                                                consent=self.ledger, vault=self.vault)
        self.keys = api.ApiKeys(); self.key = self.keys.create('partner')
        self.server, _ = api.serve(self.service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
        self.url = 'http://127.0.0.1:%d' % self.server.server_port
        self.c = sdk.Client(self.url, self.key, retries=0)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.store.close()
        # Windows will not delete a database file that is still open: close the consent DBs first.
        for db in (getattr(self, 'ledger', None), getattr(self, 'vault', None)):
            if db is not None: db.close()
        self.tmp.cleanup()

    def create(self, client=None, ref='cust-1', ctx=None, idem=None):
        return (client or self.c).create_authorization('Rahul', 'rahul@demo', '100', customer_ref=ref, context=ctx,
                                                       idempotency_key=idem)

    def count(self): return self.store.db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]

    def code(self, fn, *a, **k):
        with self.assertRaises(sdk.QuantaVoiceError) as cm: fn(*a, **k)
        return cm.exception.status, cm.exception.code


class ApiEnforcement(Env):
    def test_biometric_evidence_without_consent_is_refused_and_creates_nothing(self):
        self.assertEqual(self.code(self.create, ctx=BOTH), (403, 'consent_required'))
        self.assertEqual(self.count(), 0)
        events = [e['event'] for e in self.audit._entries()]
        self.assertIn('consent.denied', events)

    def test_grant_then_create_works(self):
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1')
        self.assertEqual(self.create(ctx=BOTH)['status'], 'pending_review')

    def test_each_score_needs_its_own_purpose(self):
        self.c.grant_consent('cust-1', ['voice_verification'], 'v1')
        self.assertEqual(self.create(ctx={'asv_score': 0.9})['status'], 'pending_review')
        self.assertEqual(self.code(self.create, ctx={'cm_score': 0.9}), (403, 'consent_required'))

    def test_no_biometric_evidence_needs_no_consent(self):
        self.assertEqual(self.create(ctx={'hour': 14, 'channel': 'app'})['status'], 'pending_review')

    def test_customer_ref_required_when_evidence_is_sent(self):
        self.assertEqual(self.code(self.create, ref=None, ctx=BOTH), (400, 'customer_ref_required'))

    def test_expired_consent_is_refused(self):
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1', ttl_days=1)
        self.clock.t += 2 * 86400
        self.assertEqual(self.code(self.create, ctx=BOTH), (403, 'consent_required'))

    def test_consent_is_not_shared_between_api_keys(self):
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1')
        other = sdk.Client(self.url, self.keys.create('other'), retries=0)
        self.assertEqual(self.code(self.create, client=other, ctx=BOTH), (403, 'consent_required'))
        self.assertFalse(other.consent_status('cust-1')['purposes']['voice_verification'])

    def test_withdrawal_after_creation_stops_the_payment(self):
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1')
        r = self.create(ctx=BOTH)
        self.store.approve_from_console(r['id'])
        self.c.withdraw_consent('cust-1')
        status, code = self.code(self.c.confirm_authorization, r['id'], r['digest'])
        self.assertEqual((status, code), (403, 'consent_withdrawn'))
        row = self.store.db.execute('SELECT status FROM transactions WHERE id=?', (r['id'],)).fetchone()
        self.assertNotEqual(row['status'], 'consumed')

    def test_confirm_still_works_while_consent_is_valid(self):
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1')
        r = self.create(ctx=BOTH)
        if r['step_up_required']:
            ch = self.c.issue_challenge(r['id']); spoken = ch['spoken_form']
            self.assertTrue(self.c.verify_challenge(r['id'], ch['challenge_id'], spoken)['verified'])
        self.store.approve_from_console(r['id'])
        self.assertEqual(self.c.confirm_authorization(r['id'], r['digest'])['status'], 'consumed')

    def test_idempotent_replay_still_replays(self):
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1')
        a = self.create(ctx=BOTH, idem='idem-12345678'); b = self.create(ctx=BOTH, idem='idem-12345678')
        self.assertEqual(a['id'], b['id']); self.assertEqual(self.count(), 1)

    def test_audit_never_holds_the_customer_reference(self):
        self.c.grant_consent('cust-secret-777', ['voice_verification'], 'v1')
        self.code(self.create, ref='cust-secret-777', ctx={'cm_score': 0.9})
        self.c.withdraw_consent('cust-secret-777'); self.c.erase_customer_data('cust-secret-777')
        text = self.audit.path.read_text(encoding='utf-8')
        self.assertNotIn('cust-secret-777', text)
        for ev in ('consent.granted', 'consent.denied', 'consent.withdrawn', 'consent.erased'): self.assertIn(ev, text)
        self.assertTrue(self.audit.verify()[0] if isinstance(self.audit.verify(), tuple) else self.audit.verify())

    def test_scopes(self):
        ro = sdk.Client(self.url, self.keys.create('ro', scopes=('authorizations:read',)), retries=0)
        self.assertEqual(self.code(ro.grant_consent, 'cust-1', ['anti_spoofing'], 'v1'), (403, 'insufficient_scope'))
        reader = sdk.Client(self.url, self.keys.create('rd', scopes=('consents:read',)), retries=0)
        self.assertTrue(reader.consent_status('cust-1')['enforced'])
        self.assertEqual(self.code(reader.withdraw_consent, 'cust-1'), (403, 'insufficient_scope'))

    def test_bad_inputs_are_rejected(self):
        raw = lambda path, body: self.c._request('POST', path, body)
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': ['sell_data'], 'notice_version': 'v1'})[1], 'invalid_purpose')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': [], 'notice_version': 'v1'})[1], 'invalid_purpose')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': ['anti_spoofing', 'anti_spoofing'], 'notice_version': 'v1'})[1], 'invalid_purpose')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': ['anti_spoofing'], 'notice_version': 'bad version!'})[1], 'invalid_notice_version')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': ['anti_spoofing'], 'notice_version': 'v1', 'ttl_days': 0})[1], 'invalid_ttl')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': ['anti_spoofing'], 'notice_version': 'v1', 'ttl_days': True})[1], 'invalid_ttl')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'a b', 'purposes': ['anti_spoofing'], 'notice_version': 'v1'})[1], 'invalid_customer_ref')
        self.assertEqual(self.code(raw, '/v1/consents', {'customer_ref': 'c', 'purposes': ['anti_spoofing'], 'notice_version': 'v1', 'extra': 1})[1], 'invalid_request')
        self.assertEqual(self.code(raw, '/v1/consents/withdraw', {'customer_ref': 'c', 'purpose': 'nope'})[1], 'invalid_purpose')
        with self.assertRaises(ValueError): self.c.consent_status('../etc')

    def test_status_reports_history_but_no_biometric_content(self):
        self.c.grant_consent('cust-1', ['voice_verification'], 'v1')
        st = self.c.consent_status('cust-1')
        self.assertEqual(st['purposes'], {'voice_verification': True, 'anti_spoofing': False, 'audit_evidence': False})
        self.assertEqual(st['history'][0]['notice_version'], 'v1')
        self.assertNotIn('embedding', json.dumps(st))

    def test_erase_withdraws_everything_and_deletes_the_voiceprint(self):
        raw = '%s:%s' % (self.key.split('.')[0][4:], 'cust-1')
        self.c.grant_consent('cust-1', ['voice_verification', 'anti_spoofing'], 'v1')
        self.vault.store(raw, b'voiceprint-bytes')
        out = self.c.erase_customer_data('cust-1')
        self.assertTrue(out['template_erased']); self.assertEqual(out['withdrawn'], 2)
        self.assertFalse(any(out['purposes'].values()))
        with self.assertRaises(Exception): self.vault.load(raw)
        self.assertEqual(len(self.vault.erasure_receipts()), 1)
        self.assertEqual(self.code(self.create, ctx=BOTH), (403, 'consent_required'))

    def test_openapi_documents_consent(self):
        paths = self.c._request('GET', '/v1/openapi.json')['paths']
        for p in ('/v1/consents', '/v1/consents/withdraw', '/v1/consents/erase', '/v1/consents/{ref}'): self.assertIn(p, paths)


class NotEnforced(Env):
    enforce = False

    def test_v17_behaviour_is_unchanged(self):
        self.assertEqual(self.create(ctx=BOTH)['status'], 'pending_review')
        self.assertEqual(self.c.consent_status('cust-1'), {'enforced': False, 'purposes': {}})
        self.assertEqual(self.code(self.c.grant_consent, 'cust-1', ['anti_spoofing'], 'v1'), (501, 'not_available'))


class DesktopFlow(Env):
    def flow(self, bridge=None):
        f = Flow(gateway=bridge or gb.GatewayBridge(self.url, self.key, customer_ref='desktop-gui'))
        f.start('Rahul', '100', 'demo-rahul', 'lunch'); return f

    def test_gate_blocks_until_consent_and_discards_evidence(self):
        f = self.flow()
        with self.assertRaises(ValueError) as cm: f.consent_gate()
        self.assertIn('Consent needed', str(cm.exception))
        with self.assertRaises(ValueError): f.record_voice_evidence(GOOD, CFG)
        self.assertIsNone(f.voice_evidence)
        f.consent_grant(); f.consent_gate()
        self.assertTrue(f.record_voice_evidence(GOOD, CFG))
        self.assertIn('GIVEN', f.describe_consent(f.consent))

    def test_withdraw_discards_recorded_evidence(self):
        f = self.flow(); f.consent_grant(); f.consent_gate(); f.record_voice_evidence(GOOD, CFG)
        self.assertIsNotNone(f.voice_evidence)
        f.consent_withdraw()
        self.assertIsNone(f.voice_evidence); self.assertIn('NOT GIVEN', f.describe_consent(f.consent))

    def test_api_submit_does_not_send_evidence_after_withdrawal(self):
        f = self.flow(); f.consent_grant(); f.consent_gate(); f.record_voice_evidence(GOOD, CFG)
        self.c.withdraw_consent('desktop-gui')  # withdrawn elsewhere, desktop still holds evidence
        f.stage = 7
        with self.assertRaises(ValueError): f.api_submit(hour=14)
        self.assertIsNone(f.voice_evidence); self.assertEqual(self.count(), 0)

    def test_erase(self):
        f = self.flow(); f.consent_grant(); f.consent_erase()
        self.assertFalse(any(f.consent['purposes'].values()))

    def test_outage_fails_closed(self):
        f = self.flow(); self.server.shutdown(); self.server.server_close()
        with self.assertRaises(ValueError) as cm: f.consent_gate()
        self.assertIn('no local fallback', str(cm.exception).lower())

    def test_broken_gateway_fails_closed(self):
        f = Flow(gateway=gb.GatewayBridge.broken('bad config'))
        for fn in (f.consent_gate, f.consent_grant, f.consent_withdraw, f.consent_erase):
            with self.assertRaises(ValueError): fn()

    def test_not_enforced_gateway_needs_no_consent(self):
        self.service.consent = None
        f = self.flow(); f.consent_gate(); f.record_voice_evidence(GOOD, CFG)
        self.assertIn('does not enforce', f.describe_consent(f.consent))


class Notice(unittest.TestCase):
    def test_notice_names_every_purpose_and_the_user_rights(self):
        from consent_notice import NOTICE_TEXT, NOTICE_VERSION, DESKTOP_PURPOSES
        for p in DESKTOP_PURPOSES: self.assertIn(p, NOTICE_TEXT)
        for word in ('withdraw', 'erase', 'draft', 'retention'): self.assertIn(word, NOTICE_TEXT.lower())
        self.assertRegex(NOTICE_VERSION, api.NOTICE_PATTERN)


class CbomVersion(unittest.TestCase):
    def test_cbom_reports_the_app_version_not_16_0(self):
        import cbom
        comp = cbom.build_cbom()['metadata']['component']
        self.assertEqual(comp['version'], cbom.APP_VERSION); self.assertNotEqual(comp['version'], '16.0')
        shipped = json.loads((Path(__file__).resolve().parent.parent / 'QuantaVoice_CBOM.json').read_text(encoding='utf-8'))
        self.assertEqual(shipped['metadata']['component']['version'], cbom.APP_VERSION)


# ---- GUI (needs a display; skipped without one, like test_v17_gui) ----
import os
import time
import tkinter as tk
from unittest import mock

from test_v17_gui import GuiBase, texts

class GuiConsent(GuiBase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory(); d = Path(self.tmp.name)
        self.store = BackendStore(d / 'l.db', demo=True, provider='hybrid')
        self.audit = AuditLog(d / 'a.jsonl')
        self.ledger = ConsentLedger(d / 'c.db', master_key=b'k' * 32)
        service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService(),
                                           consent=self.ledger, vault=TemplateVault(d / 't.db', self.ledger))
        self.keys = api.ApiKeys(); key = self.keys.create('gui')
        self.server, _ = api.serve(service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
        self.addCleanup(self._stop_gateway)                # registered before anything else can fail
        os.environ['QUANTAVOICE_API_URL'] = 'http://127.0.0.1:%d' % self.server.server_port
        os.environ['QUANTAVOICE_API_KEY'] = key
        self.app = self.ResearchVoice(self.root); self.app.presentation.set(True)
        self.cfg = Path(tempfile.mkdtemp()) / 'c.json'; self.cfg.write_text(json.dumps(CFG))

    def _stop_gateway(self):
        for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
        if getattr(self, 'server', None) is not None:         # outage tests stop the server themselves and set it to None
            self.server.shutdown(); self.server.server_close()
        self.store.close()
        for db in (getattr(self, 'ledger', None), getattr(self, 'vault', None)):
            if db is not None: db.close()
        self.tmp.cleanup()

    def run_voice(self):
        self.app.mic.last_audio = (b'\0\0' * 16000, 16000, time.monotonic())
        scores = {'asv': 0.8, 'cm': 4.0, 'asv_ms': 1.0, 'cm_ms': 1.0, 'passed': True}
        calls = []
        def fake(*a): calls.append(1); return scores
        with mock.patch('evidence.config_path', lambda: self.cfg), mock.patch('research.score_live', fake):
            self.app.voice_verify(); self.pump()
        return calls

    def test_privacy_button_shown_in_api_mode(self):
        self.app.flow.start('Rahul', '100', 'demo-rahul'); self.app.render()
        shown = ' | '.join(texts(self.app.panel))
        self.assertIn('Privacy & consent', shown); self.assertIn('Consent status not checked yet', shown)

    def test_no_consent_means_voice_is_never_scored(self):
        self.app.flow.start('Rahul', '100', 'demo-rahul')
        calls = self.run_voice()
        self.assertEqual(calls, [])                      # the model never ran
        self.assertEqual(self.app.flow.stage, 0); self.assertIsNone(self.app.flow.voice_evidence)
        self.assertTrue(any('Consent needed' in e for e in self.errors))

    def test_dialog_grant_then_voice_runs_then_withdraw_discards(self):
        f = self.app.flow; f.start('Rahul', '100', 'demo-rahul')
        self.app.privacy_dialog(); self.pump()
        shown = ' | '.join(texts(self.app.consent_top))
        for label in ('I agree (voice verification + anti-spoofing)', 'Withdraw consent', 'Erase my voice data'):
            self.assertIn(label, shown)
        self.assertIn('NOT GIVEN', self.app.consent_state_var.get())
        self.app.background(f.consent_grant, lambda s: self.app.consent_state_var.set(f.describe_consent(s))); self.pump()
        self.assertIn('voice verification GIVEN', self.app.consent_state_var.get())
        self.assertEqual(len(self.run_voice()), 1)
        self.assertEqual(f.stage, 1); self.assertIsNotNone(f.voice_evidence)
        self.app.background(f.consent_withdraw, lambda s: None); self.pump()
        self.assertIsNone(f.voice_evidence)
        self.app.consent_top.destroy()

    def test_outage_during_gate_blocks_voice(self):
        self.app.flow.start('Rahul', '100', 'demo-rahul')
        self.server.shutdown(); self.server.server_close()
        calls = self.run_voice()
        self.assertEqual(calls, []); self.assertTrue(any('no local fallback' in e.lower() for e in self.errors))
        self.server = None; self.store.close()
        for db in (getattr(self, 'ledger', None), getattr(self, 'vault', None)):
            if db is not None: db.close()
        self.tmp.cleanup(); self.store = mock.Mock(); self.tmp = mock.Mock()


if __name__ == '__main__':
    unittest.main()
