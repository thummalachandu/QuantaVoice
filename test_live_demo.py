"""v17.3: the live demo page is driven by the real engine; honest labels; loopback-only server."""
import http.client
import json
import unittest

import live_demo_server as demo
from seven_flow import NAMES


class Engine(unittest.TestCase):
    def test_legitimate_passes_all_seven_and_moves_simulated_money(self):
        r = demo.run_scenario('legitimate')
        self.assertEqual(r['verdict'], 'approved'); self.assertIsNone(r['blocked_at'])
        self.assertEqual([l['status'] for l in r['layers']], ['PASSED'] * 7)
        self.assertEqual(r['payment']['balance_before'] - r['payment']['balance_after'], 5000)
        self.assertEqual(r['payment']['suite'], 'ML-KEM-768 + AES-256-GCM + ML-DSA-65'); self.assertGreater(r['payment']['encrypt_ms'], 0)

    def test_each_attack_is_blocked_at_its_layer_and_no_money_moves(self):
        for name, layer in (('deepfake', 1), ('cloning', 1), ('hijack', 5), ('wrong_pin', 2)):
            r = demo.run_scenario(name)
            self.assertEqual((r['verdict'], r['blocked_at']), ('blocked', layer), name)
            self.assertEqual(r['layers'][layer - 1]['status'], 'REJECTED')
            self.assertTrue(all(l['status'] == 'PASSED' for l in r['layers'][:layer - 1]))
            self.assertTrue(all(l['status'] == 'NOT REACHED' for l in r['layers'][layer:]))
            self.assertEqual(r['payment']['balance_before'], r['payment']['balance_after']); self.assertNotIn('suite', r['payment'])

    def test_wrong_pin_uses_the_real_lockout(self):
        self.assertIn('Three incorrect PIN attempts', demo.run_scenario('wrong_pin')['layers'][1]['detail'])

    def test_layer_names_come_from_the_engine_and_real_vs_simulated_is_labelled(self):
        m = demo.meta()
        self.assertEqual([l['name'] for l in m['layers']], NAMES)
        self.assertEqual([l['kind'] for l in m['layers']], ['SIMULATED', 'REAL', 'REAL'] + ['SIMULATED'] * 4)

    def test_unknown_scenario_is_refused(self):
        with self.assertRaises(ValueError): demo.run_scenario('drop table')

    def test_amount_is_within_the_engine_limit(self):
        self.assertLessEqual(float(demo.AMOUNT), 50000)


class Page(unittest.TestCase):
    def test_page_is_honest_and_calls_the_engine(self):
        html = demo.PAGE.read_text(encoding='utf-8')
        for banned in ('Math.random', '98.7', '99.99%', 'ECAPA-TDNN', 'AASIST', '5,00,000'):
            self.assertNotIn(banned, html)
        for needed in ('/api/run', '/api/meta', 'SIMULATED', 'START_LIVE_DEMO.cmd'):
            self.assertIn(needed, html)


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.server = demo.serve(port=0); cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls): cls.server.shutdown(); cls.server.server_close()

    def call(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse(); data = r.read(); c.close(); return r, data

    def test_serves_page_with_security_headers(self):
        r, data = self.call('GET', '/')
        self.assertEqual(r.status, 200); self.assertIn(b'QuantaVoice Live Security Demo', data)
        self.assertIn("default-src 'none'", r.getheader('Content-Security-Policy')); self.assertEqual(r.getheader('X-Content-Type-Options'), 'nosniff')

    def test_run_over_http_matches_the_engine(self):
        r, data = self.call('POST', '/api/run', json.dumps({'scenario': 'hijack'}), {'Content-Type': 'application/json'})
        out = json.loads(data); self.assertEqual((r.status, out['verdict'], out['blocked_at']), (200, 'blocked', 5))

    def test_bad_requests(self):
        post = lambda b, h=None: self.call('POST', '/api/run', b, dict({'Content-Type': 'application/json'}, **(h or {})))
        self.assertEqual(post(json.dumps({'scenario': 'nope'}))[0].status, 400)
        self.assertEqual(post(json.dumps({'scenario': 5}))[0].status, 400)
        self.assertEqual(post(b'not json')[0].status, 400)
        self.assertEqual(post(b'x' * 5000)[0].status, 413)
        self.assertEqual(self.call('GET', '/nothing')[0].status, 404)
        self.assertEqual(self.call('POST', '/api/meta', b'{}')[0].status, 404)

    def test_dns_rebinding_and_cross_site_posts_are_refused(self):
        self.assertEqual(self.call('GET', '/api/meta', headers={'Host': 'evil.example'})[0].status, 403)
        r, _ = self.call('POST', '/api/run', json.dumps({'scenario': 'legitimate'}), {'Origin': 'http://evil.example'})
        self.assertEqual(r.status, 403)

    def test_refuses_non_loopback_bind(self):
        for host in ('0.0.0.0', '192.168.1.5'):
            with self.assertRaises(ValueError): demo.serve(host=host)


if __name__ == '__main__':
    unittest.main()
