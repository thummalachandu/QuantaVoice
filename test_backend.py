import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sys
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer

from backend_store import BackendStore, provider_for
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend_lab import handler_for
from backend_client import Client

DETAILS = {'recipient': 'Chandu', 'destination': 'chandu@demo', 'rupees': '5000', 'note': ''}

class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'ledger.sqlite3'
        self.now = 1000.0
        self.store = BackendStore(self.path, demo=True, clock=lambda: self.now)
        self.token = self.store.session(self.store.bootstrap_token)['token']

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def prepared(self):
        return self.store.prepare(self.token, dict(DETAILS))

    def approved(self):
        result = self.prepared()
        self.store.approve_from_console(result['intent']['id'])
        return {'id': result['intent']['id'], 'digest': result['digest']}

    def test_confirm_requires_independent_review(self):
        result = self.prepared()
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, {'id': result['intent']['id'], 'digest': result['digest']})
        self.assertEqual(self.store.status(self.token)['balance_paise'], 5000000)

    def test_duplicate_concurrent_confirm_debits_once(self):
        request = self.approved()
        def confirm(_):
            try:
                return self.store.confirm(self.token, request)
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(confirm, range(8)))
        self.assertEqual(sum(x is not None for x in results), 1)
        self.assertEqual(self.store.status(self.token)['balance_paise'], 4500000)

    def test_ciphertext_tamper_keeps_balance_and_pending(self):
        request = self.approved()
        packet = self.store.packets[request['id']]
        self.store.packets[request['id']] = replace(packet, payload=bytes([packet.payload[0] ^ 1]) + packet.payload[1:])
        with self.assertRaises(Exception):
            self.store.confirm(self.token, request)
        self.assertEqual(self.store.status(self.token)['balance_paise'], 5000000)
        self.store.packets[request['id']] = packet
        self.store.confirm(self.token, request)

    def test_signature_tamper_keeps_balance(self):
        request = self.approved()
        packet = self.store.packets[request['id']]
        self.store.packets[request['id']] = replace(packet, signature=bytes([packet.signature[0] ^ 1]) + packet.signature[1:])
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, request)
        self.assertEqual(self.store.status(self.token)['balance_paise'], 5000000)

    def test_exact_review_digest_required(self):
        request = self.approved()
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, {**request, 'digest': '0' * 64})
        self.assertEqual(self.store.status(self.token)['balance_paise'], 5000000)

    def test_edit_cancels_old_operator_approval(self):
        old = self.approved()
        self.store.prepare(self.token, {**DETAILS, 'rupees': '200'})
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, old)

    def test_cross_session_cannot_consume_other_intent(self):
        request = self.approved()
        other = self.store.session(self.store.bootstrap_token)['token']
        with self.assertRaises(ValueError):
            self.store.confirm(other, request)

    def test_expiry_before_and_during_verification(self):
        request = self.approved()
        self.now = 1120.0
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, request)
        self.now = 1000.0
        original = self.store.crypto.open
        def late(packet):
            raw = original(packet)
            self.now = 1121.0
            return raw
        self.store.crypto.open = late
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, request)
        self.assertEqual(self.store.status(self.token)['balance_paise'], 5000000)

    def test_invalid_session_and_client_approval_flags(self):
        with self.assertRaises(PermissionError):
            self.store.prepare('wrong', dict(DETAILS))
        with self.assertRaises(ValueError):
            self.store.prepare(self.token, {**DETAILS, 'approved': True})
        self.now = 2800.0
        with self.assertRaises(PermissionError):
            self.store.status(self.token)

    def test_real_destination_and_invalid_amounts_rejected(self):
        with self.assertRaises(ValueError):
            self.store.prepare(self.token, {**DETAILS, 'destination': 'chandu@upi'})
        for amount in ['0', '-1', 'NaN', 'Infinity', '0.001', '50001', 'abc']:
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                self.store.prepare(self.token, {**DETAILS, 'rupees': amount})

    def test_insufficient_balance_rollback(self):
        request = self.approved()
        self.store.db.execute('UPDATE account SET balance=1')
        with self.assertRaises(ValueError):
            self.store.confirm(self.token, request)
        self.assertEqual(self.store.db.execute('SELECT status FROM transactions WHERE id=?', (request['id'],)).fetchone()[0], 'approved')
        self.assertEqual(self.store.status(self.token)['balance_paise'], 1)

    def test_restart_preserves_receipt_and_cancels_pending(self):
        consumed = self.approved()
        self.store.confirm(self.token, consumed)
        pending = self.approved()
        self.store.close()
        self.store = BackendStore(self.path, demo=True, clock=lambda: self.now)
        self.token = self.store.session(self.store.bootstrap_token)['token']
        self.assertEqual(self.store.status(self.token)['balance_paise'], 4500000)
        for request in [consumed, pending]:
            with self.assertRaises(ValueError):
                self.store.confirm(self.token, request)
        self.assertEqual(self.store.db.execute('SELECT status FROM transactions WHERE id=?', (consumed['id'],)).fetchone()[0], 'consumed')

    def test_rotation_revokes_old_session_and_pending(self):
        request = self.approved()
        old = self.store.crypto.fingerprint
        self.store.rotate()
        self.assertNotEqual(old, self.store.crypto.fingerprint)
        with self.assertRaises(PermissionError):
            self.store.confirm(self.token, request)

    def test_default_mode_and_qnu_fail_closed(self):
        self.store.demo = False
        request = self.prepared()
        with self.assertRaises(PermissionError):
            self.store.approve_from_console(request['intent']['id'])
        with self.assertRaisesRegex(RuntimeError, 'NOT integrated'):
            provider_for('qnu')

    def test_http_end_to_end_and_unavailable_approval_route(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(self.store))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            client = Client({'port': server.server_port, 'bootstrap': self.store.bootstrap_token,
                             'fingerprint': self.store.crypto.fingerprint})
            created = client.call('/prepare', dict(DETAILS))
            with self.assertRaises(ValueError):
                client.call('/approve', {'id': created['intent']['id']})
            request = {'id': created['intent']['id'], 'digest': created['digest']}
            with self.assertRaises(ValueError):
                client.call('/confirm', request)
            self.store.approve_from_console(request['id'])
            self.assertEqual(client.call('/confirm', request)['balance_paise'], 4500000)
            with self.assertRaises(ValueError):
                client.call('/confirm', request)
            opener = build_opener(ProxyHandler({}))
            for extra in [{'Origin': 'https://example.test'}, {'Authorization': 'Bearer wrong'}, {'Host': 'evil.example'}]:
                headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + client.token, **extra}
                req = Request(client.url + '/status', data=b'{}', headers=headers)
                with self.assertRaises(HTTPError) as error:
                    opener.open(req, timeout=5)
                self.assertEqual(error.exception.code, 403)
                error.exception.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_client_checks_launch_key_fingerprint(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(self.store))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                Client({'port': server.server_port, 'bootstrap': self.store.bootstrap_token, 'fingerprint': 'wrong'})
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
