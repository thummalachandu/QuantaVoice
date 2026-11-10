import json
import tempfile
import unittest
from pathlib import Path

import audit_log
import cbom
import crypto_agility
import hybrid_kex
import provider_adapters as pa
from backend_store import BackendStore


class HybridKex(unittest.TestCase):
    def test_roundtrip_and_context_binding(self):
        pub, priv = hybrid_kex.generate()
        ct, secret = hybrid_kex.encapsulate(pub, b'ctx')
        self.assertEqual(len(secret), 32)
        self.assertEqual(secret, hybrid_kex.decapsulate(pub, priv, ct, b'ctx'))
        self.assertNotEqual(secret, hybrid_kex.decapsulate(pub, priv, ct, b'other'))

    def test_tampered_ciphertext_changes_secret_or_fails(self):
        pub, priv = hybrid_kex.generate()
        ct, secret = hybrid_kex.encapsulate(pub)
        for index in (0, 40, len(ct) - 1):  # classical part, PQ part, PQ tail
            bad = bytearray(ct); bad[index] ^= 1
            try:
                self.assertNotEqual(secret, hybrid_kex.decapsulate(pub, priv, bytes(bad)))
            except Exception:
                pass

    def test_low_order_x25519_point_rejected(self):
        pub, _ = hybrid_kex.generate()
        with self.assertRaises(ValueError):
            hybrid_kex.encapsulate(hybrid_kex.HybridPublic(bytes(32), pub.mlkem))

    def test_fresh_secret_each_time(self):
        pub, _ = hybrid_kex.generate()
        self.assertNotEqual(hybrid_kex.encapsulate(pub)[1], hybrid_kex.encapsulate(pub)[1])

    def test_hybrid_backend_provider_full_payment(self):
        with tempfile.TemporaryDirectory() as d:
            store = BackendStore(Path(d) / 'l.db', demo=True, provider='hybrid')
            token = store.session(store.bootstrap_token)['token']
            r = store.prepare(token, {'recipient': 'Chandu', 'destination': 'chandu@demo', 'rupees': '10', 'note': ''})
            store.approve_from_console(r['intent']['id'])
            out = store.confirm(token, {'id': r['intent']['id'], 'digest': r['digest']})
            self.assertEqual(out['balance_paise'], 5000000 - 1000)
            with self.assertRaises(ValueError):
                store.confirm(token, {'id': r['intent']['id'], 'digest': r['digest']})
            fingerprint = store.rotate()
            self.assertEqual(len(fingerprint), 64)
            self.assertIn('hybrid', store.crypto.name)
            store.close()


class Audit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'audit.jsonl'
        self.log = audit_log.AuditLog(self.path)
        for i in range(5):
            self.log.append('event.%d' % i, {'n': i})

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_chain(self):
        self.assertEqual(self.log.verify(), (True, 5, 'ok'))

    def test_edit_detected(self):
        lines = self.path.read_text().splitlines()
        e = json.loads(lines[2]); e['data']['n'] = 99
        lines[2] = json.dumps(e, sort_keys=True)
        self.path.write_text('\n'.join(lines) + '\n')
        self.assertFalse(self.log.verify()[0])

    def test_deleted_middle_entry_detected(self):
        lines = self.path.read_text().splitlines()
        del lines[2]
        self.path.write_text('\n'.join(lines) + '\n')
        self.assertFalse(self.log.verify()[0])

    def test_truncation_needs_checkpoint(self):
        cp = self.log.checkpoint()
        lines = self.path.read_text().splitlines()[:3]
        self.path.write_text('\n'.join(lines) + '\n')
        self.assertTrue(self.log.verify()[0])  # chain alone cannot see it
        ok, _, msg = self.log.verify(checkpoint=cp)
        self.assertFalse(ok); self.assertIn('truncated', msg)

    def test_forged_signature_detected(self):
        other = audit_log.AuditLog(Path(self.tmp.name) / 'other.jsonl')
        self.assertFalse(self.log.verify(public=other.public)[0])

    def test_secrets_are_redacted(self):
        e = self.log.append('x', {'api_token': 'abc', 'card_pan': '4111', 'amount': 5, 'nested': {'otp': '1'}})
        self.assertEqual(e['data']['api_token'], '[REDACTED]')
        self.assertEqual(e['data']['card_pan'], '[REDACTED]')
        self.assertEqual(e['data']['nested']['otp'], '[REDACTED]')
        self.assertEqual(e['data']['amount'], 5)

    def test_reopen_continues_chain(self):
        again = audit_log.AuditLog(self.path, keypair=(self.log.public, self.log.private))
        again.append('later')
        self.assertEqual(again.verify(), (True, 6, 'ok'))

    def test_reopen_corrupt_refuses(self):
        self.path.write_text(self.path.read_text().replace('"n": 1', '"n": 7'))
        with self.assertRaises(ValueError):
            audit_log.AuditLog(self.path, keypair=(self.log.public, self.log.private))

    def test_cef_export_escapes(self):
        self.log.append('authorization.declined', {'reason': 'a|b=c'})
        lines = self.log.export_cef()
        self.assertEqual(len(lines), 6)
        self.assertTrue(lines[-1].startswith('CEF:0|QuantaVoice|VoiceAuth|16|authorization.declined'))
        self.assertIn('a\\|b\\=c', lines[-1])


class Providers(unittest.TestCase):
    def test_cutoffs_match_sp800_90b(self):
        h = pa.HealthTests()
        self.assertEqual(h.rct_cutoff, 4)
        self.assertTrue(10 <= h.apt_cutoff <= 20)

    def test_repetition_failure(self):
        with self.assertRaises(pa.EntropyFailure):
            pa.HealthTests().feed(b'\x00' * 10)

    def test_proportion_failure(self):
        with self.assertRaises(pa.EntropyFailure):
            pa.HealthTests().feed(bytes([7, 1] * 300))

    def test_good_entropy_passes(self):
        import os
        pa.HealthTests().feed(os.urandom(100000))

    def test_qrng_fails_closed_without_device(self):
        with self.assertRaises(pa.NotConnected):
            pa.QRNGSource().read(32)

    def test_qrng_bad_device_rejected_not_hidden(self):
        with self.assertRaises(pa.EntropyFailure):
            pa.QRNGSource(fetch=lambda n: b'\x00' * n).read(32)

    def test_qrng_mixes_with_os_entropy(self):
        import os
        src = pa.QRNGSource(fetch=lambda n: os.urandom(n))
        self.assertNotEqual(src.read(32), src.read(32))

    def test_qkd_not_configured(self):
        with self.assertRaises(pa.NotConnected):
            pa.QKDKeyClient().get_key('slave')

    def test_qkd_etsi_shape_with_mock_transport(self):
        import base64, os
        key = os.urandom(32)
        def transport(method, path, body):
            self.assertEqual((method, path), ('POST', '/api/v1/keys/bank-sae/enc_keys'))
            self.assertEqual(body, {'number': 1, 'size': 256})
            return {'keys': [{'key_ID': 'kid-1', 'key': base64.b64encode(key).decode()}]}
        kid, got = pa.QKDKeyClient(transport).get_key('bank-sae')
        self.assertEqual((kid, got), ('kid-1', key))

    def test_qkd_wrong_size_rejected(self):
        import base64
        t = lambda m, p, b: {'keys': [{'key_ID': 'k', 'key': base64.b64encode(b'x' * 16).decode()}]}
        with self.assertRaises(pa.EntropyFailure):
            pa.QKDKeyClient(t).get_key('s')

    def test_software_keystore_roundtrip_and_wrong_pass(self):
        with tempfile.TemporaryDirectory() as d:
            ks = pa.SoftwareKeyStore(Path(d) / 'ks.json', 'a long passphrase!')
            ks.put('k1', b'secret-bytes')
            self.assertEqual(ks.get('k1'), b'secret-bytes')
            self.assertNotIn('secret-bytes', (Path(d) / 'ks.json').read_text())
            with self.assertRaises(Exception):
                pa.SoftwareKeyStore(Path(d) / 'ks.json', 'wrong passphrase!!').get('k1')
            with self.assertRaises(ValueError):
                pa.SoftwareKeyStore(Path(d) / 'x.json', 'short')

    def test_hsm_fails_closed_and_status_is_honest(self):
        with self.assertRaises(pa.NotConnected):
            pa.HSMKeyStore()
        status = pa.provider_status()
        for name in ('qrng', 'qkd', 'hsm'):
            self.assertTrue(status[name].startswith('not connected'))


class AgilityAndCbom(unittest.TestCase):
    def test_classical_only_refused(self):
        with self.assertRaises(ValueError):
            crypto_agility.negotiate(['x25519+ed25519+aes256gcm'])

    def test_server_preference_and_binding(self):
        offer = ['mlkem768+mldsa65+aes256gcm', 'hybrid-x25519-mlkem768+mldsa65+aes256gcm']
        chosen, binding = crypto_agility.negotiate(offer)
        self.assertEqual(chosen, 'hybrid-x25519-mlkem768+mldsa65+aes256gcm')
        self.assertTrue(crypto_agility.check_binding(offer, chosen, binding))
        self.assertFalse(crypto_agility.check_binding(offer[:1], chosen, binding))  # offer edited in transit

    def test_policy_cannot_include_classical(self):
        with self.assertRaises(ValueError):
            crypto_agility.negotiate(['x25519+ed25519+aes256gcm'], ['x25519+ed25519+aes256gcm'])

    def test_cbom_structure(self):
        b = cbom.build_cbom()
        self.assertEqual((b['bomFormat'], b['specVersion']), ('CycloneDX', '1.6'))
        names = {c['name'] for c in b['components']}
        self.assertTrue({'ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM', 'pqcrypto'} <= names)
        kem = next(c for c in b['components'] if c['name'] == 'ML-KEM-768')
        self.assertEqual(kem['cryptoProperties']['oid'], '2.16.840.1.101.3.4.4.2')
        json.dumps(b)

    def test_compliance_map_makes_no_certification_claims(self):
        rows = cbom.compliance_map(pa.provider_status())
        status = {r['control']: r['status'] for r in rows}
        self.assertEqual(status['PCI DSS'], 'not claimed')
        self.assertEqual(status['ISO/IEC 27001'], 'not claimed')
        self.assertEqual(status['HSM / PKCS#11'], 'not implemented')


if __name__ == '__main__':
    unittest.main()
