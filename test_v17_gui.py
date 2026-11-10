import json
import os
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import api_gateway as api
import challenge_phrase
import evidence
import gateway_bridge as gb
from audit_log import AuditLog
from backend_store import BackendStore

CFG = {'asv_threshold': 0.4, 'cm_threshold': 1.5, 'thresholds_from_dev': True}


def texts(widget):
    out = []
    for w in widget.winfo_children():
        try: out.append(str(w.cget('text')))
        except tk.TclError: pass
        out.extend(texts(w))
    return out


def try_root():
    try:
        r = tk.Tk(); r.withdraw(); return r
    except tk.TclError:
        return None


NO_DISPLAY_MSG = ('No display available for Tk. The GUI tests are never skipped: run them through run_tests.py '
                  '(it starts a virtual display on headless Linux) or on a machine with a desktop session.')


class GuiBase(unittest.TestCase):
    def setUp(self):
        self.root = try_root()
        if self.root is None: self.fail(NO_DISPLAY_MSG)       # fail loudly, never skip silently
        self.addCleanup(self._destroy_root)                    # registered first, so it runs last
        for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
        self.errors, self.infos = [], []
        patches = [mock.patch('research_ui.messagebox.showerror', lambda t, m, **k: self.errors.append(m)),
                   mock.patch('research_ui.messagebox.showwarning', lambda t, m, **k: self.errors.append(m)),
                   mock.patch('research_ui.messagebox.showinfo', lambda t, m, **k: self.infos.append(m)),
                   mock.patch('research_ui.messagebox.askyesno', lambda *a, **k: True),
                   mock.patch('evidence.DATA', Path(tempfile.mkdtemp())),
                   mock.patch('gateway_bridge.DATA', Path(tempfile.mkdtemp()))]
        for p in patches:
            p.start(); self.addCleanup(p.stop)                 # restored even if a later setUp step raises
        from research_ui import ResearchVoice
        self.ResearchVoice = ResearchVoice

    def _destroy_root(self):
        if getattr(self, 'app', None) is not None: self.app.closing = True
        for after_id in self.root.tk.call('after', 'info'):
            self.root.after_cancel(after_id)
        self.root.destroy()

    def pump(self, seconds=8):
        end = time.time() + seconds
        while time.time() < end:
            self.root.update(); time.sleep(0.01)
            if not self.app.task_busy and self.app.tasks.empty(): self.root.update(); return
        self.fail('background task did not finish')

    def to_stage7(self):
        f = self.app.flow
        f.start('Rahul', '100', 'demo-rahul', 'lunch')
        f.scenario(0, True); f.verify_pin('246810'); f.issue_otp(); f.verify_otp(f.otp)
        for s in (3, 4, 5, 6): f.scenario(s, True)
        self.app.render()


class NoGateway(GuiBase):
    def test_default_behaviour_is_v16(self):
        self.app = self.ResearchVoice(self.root)
        self.assertIsNone(self.app.flow.gateway)
        self.app.presentation.set(True); self.to_stage7()
        shown = ' | '.join(texts(self.app.panel))
        self.assertNotIn('Submit to API', shown)
        self.assertIn('Encrypt / renew encrypted intent', shown)

    def test_broken_config_blocks_instead_of_falling_back(self):
        os.environ['QUANTAVOICE_API_URL'] = 'http://127.0.0.1:9'; os.environ['QUANTAVOICE_API_KEY'] = 'not-a-key'
        try: self.app = self.ResearchVoice(self.root)
        finally:
            for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
        self.assertIsNotNone(self.app.flow.gateway)
        self.assertTrue(any('wrong format' in e for e in self.errors))
        self.app.presentation.set(True); self.to_stage7()
        self.assertNotIn('Encrypt / renew encrypted intent', ' | '.join(texts(self.app.panel)))
        self.app.api_submit_clicked(); self.pump()
        self.assertEqual((self.app.flow.stage, self.app.flow.blocked), (7, False))
        self.assertTrue(any('unusable' in e for e in self.errors))


class WithGateway(GuiBase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.store = BackendStore(Path(self.tmp.name) / 'l.db', demo=True, provider='hybrid')
        self.audit = AuditLog(Path(self.tmp.name) / 'a.jsonl')
        service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService())
        self.keys = api.ApiKeys(); key = self.keys.create('gui')
        self.server, _ = api.serve(service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
        self.addCleanup(self._stop_gateway)                    # registered before anything else can fail
        os.environ['QUANTAVOICE_API_URL'] = 'http://127.0.0.1:%d' % self.server.server_port
        os.environ['QUANTAVOICE_API_KEY'] = key
        self.app = self.ResearchVoice(self.root)
        self.app.presentation.set(True)

    def _stop_gateway(self):
        for k in ('QUANTAVOICE_API_URL', 'QUANTAVOICE_API_KEY'): os.environ.pop(k, None)
        if getattr(self, 'server', None) is not None:         # outage tests stop the server themselves and set it to None
            self.server.shutdown(); self.server.server_close()
        self.store.close(); self.tmp.cleanup()

    def test_stage7_shows_api_panel_not_local_buttons(self):
        self.to_stage7(); shown = ' | '.join(texts(self.app.panel))
        self.assertIn('Submit to API for risk review', shown)
        self.assertNotIn('Encrypt / renew encrypted intent', shown); self.assertNotIn('Confirm simulated payment', shown)
        self.assertIn('no voice evidence', shown)
        self.assertIn('Presentation buttons are never sent as evidence', shown)

    def test_full_gui_flow_with_step_up_and_receipt(self):
        self.to_stage7()
        self.app.api_submit_clicked(); self.pump()
        shown = ' | '.join(texts(self.app.panel))
        self.assertIn('Get spoken challenge', shown); self.assertIn('Check approval status', shown)
        shown_var = tk.StringVar(master=self.root)
        self.app.api_challenge_clicked(shown_var); self.pump()
        spoken = shown_var.get().split(': ', 1)[1]
        entry = tk.Entry(self.root); entry.insert(0, spoken)
        self.app.api_verify_clicked(entry); self.pump()
        self.assertTrue(self.app.flow.api['challenge_ok'])
        self.assertNotIn('Get spoken challenge', ' | '.join(texts(self.app.panel)))
        self.app.api_confirm_clicked(); self.pump()  # not approved by the operator yet
        self.assertEqual(self.app.flow.stage, 7); self.assertTrue(self.errors)
        self.store.approve_from_console(self.app.flow.api['id'])
        self.app.api_status_clicked(); self.pump()
        self.app.api_confirm_clicked(); self.pump()
        self.assertEqual(self.app.flow.stage, 8)
        self.assertIn('SIMULATED PAYMENT COMPLETED (via API)', ' | '.join(texts(self.app.panel)))
        self.assertTrue(any('Receipt:' in t for t in texts(self.app.panel)))

    def test_outage_shows_error_and_keeps_payment_unmade(self):
        self.to_stage7()
        self.server.shutdown(); self.server.server_close()
        self.app.api_submit_clicked(); self.pump()
        self.assertTrue(any('no local fallback' in e.lower() for e in self.errors))
        self.assertEqual((self.app.flow.stage, self.app.flow.blocked), (7, False))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0], 0)
        self.server = None; self.store.close(); self.tmp.cleanup(); self.tmp = None
        self.store = mock.Mock(); self.tmp = mock.Mock()

    def test_declined_risk_blocks_and_renders_blocked(self):
        f = self.app.flow
        f.start('Rahul', '100', 'demo-rahul', 'x')
        f.voice_evidence = evidence.voice_scores({'asv': 0.1, 'cm': -6.0, 'asv_ms': 1, 'cm_ms': 1}, CFG)  # direct, as record_* needs real stage
        f.scenario(0, True); f.verify_pin('246810'); f.issue_otp(); f.verify_otp(f.otp)
        for s in (3, 4, 5, 6): f.scenario(s, True)
        self.app.render(); self.app.api_submit_clicked(); self.pump()
        self.assertTrue(f.blocked); self.assertIn('PAYMENT BLOCKED', ' | '.join(texts(self.app.panel)))

    def test_real_voice_button_records_calibrated_evidence(self):
        cfg = Path(tempfile.mkdtemp()) / 'c.json'; cfg.write_text(json.dumps(CFG))
        self.app.flow.start('Rahul', '100', 'demo-rahul'); self.app.render()
        self.assertIn('Run real ASV + CM inference (evidence for the API)', ' | '.join(texts(self.app.panel)))
        self.app.mic.last_audio = (b'\0\0' * 16000, 16000, time.monotonic())
        scores = {'asv': 0.8, 'cm': 4.0, 'asv_ms': 1.0, 'cm_ms': 1.0, 'passed': True}
        with mock.patch('evidence.config_path', lambda: cfg), mock.patch('research.score_live', lambda *a: scores):
            self.app.voice_verify(); self.pump()
        self.assertEqual(self.app.flow.stage, 1)
        self.assertGreater(self.app.flow.voice_evidence['asv_score'], 0.5)

    def test_failed_real_voice_blocks_and_records_nothing(self):
        cfg = Path(tempfile.mkdtemp()) / 'c.json'; cfg.write_text(json.dumps(CFG))
        self.app.flow.start('Rahul', '100', 'demo-rahul'); self.app.mic.last_audio = (b'\0\0' * 16000, 16000, time.monotonic())
        scores = {'asv': 0.1, 'cm': -5.0, 'asv_ms': 1.0, 'cm_ms': 1.0, 'passed': False}
        with mock.patch('evidence.config_path', lambda: cfg), mock.patch('research.score_live', lambda *a: scores):
            self.app.voice_verify(); self.pump()
        self.assertTrue(self.app.flow.blocked); self.assertIsNone(self.app.flow.voice_evidence)


if __name__ == '__main__':
    unittest.main()
