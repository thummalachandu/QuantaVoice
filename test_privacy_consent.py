import tempfile
import unittest
from pathlib import Path

from privacy_consent import ConsentError, ConsentLedger, TemplateVault, DAY

EMB = bytes(range(192))


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class Privacy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.clock = Clock()
        self.ledger = ConsentLedger(self.dir / 'c.db', clock=self.clock)
        self.vault = TemplateVault(self.dir / 't.db', self.ledger, retention_days=30, clock=self.clock)

    def tearDown(self):
        self.vault.close()
        self.ledger.close()
        self.tmp.cleanup()

    def consent(self, who='alice@example.com'):
        self.ledger.grant(who, 'voice_verification', 'notice-v1', 90)

    def test_store_requires_consent(self):
        with self.assertRaises(ConsentError):
            self.vault.store('alice@example.com', EMB)

    def test_roundtrip(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        self.assertEqual(self.vault.load('alice@example.com'), EMB)

    def test_withdrawal_blocks_load(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        self.assertEqual(self.ledger.withdraw('alice@example.com', 'voice_verification'), 1)
        with self.assertRaises(ConsentError):
            self.vault.load('alice@example.com')

    def test_consent_expiry(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        self.clock.t += 91 * DAY
        with self.assertRaises(ConsentError):
            self.vault.load('alice@example.com')

    def test_purpose_limitation(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        with self.assertRaises(ConsentError):
            self.vault.load('alice@example.com', 'audit_evidence')
        with self.assertRaises(ConsentError):
            self.ledger.grant('alice@example.com', 'marketing', 'notice-v1')

    def test_erase_and_receipt(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        self.assertTrue(self.vault.erase('alice@example.com'))
        with self.assertRaises(KeyError):
            self.vault.load('alice@example.com')
        r = self.vault.erasure_receipts()
        self.assertEqual(len(r), 1)
        self.assertNotIn('alice', str(r))

    def test_retention_auto_erase(self):
        self.ledger.grant('alice@example.com', 'voice_verification', 'notice-v1', 365)
        self.vault.store('alice@example.com', EMB)
        self.clock.t += 31 * DAY
        with self.assertRaises(ConsentError):
            self.vault.load('alice@example.com')
        with self.assertRaises(KeyError):
            self.vault.load('alice@example.com')

    def test_purge_expired(self):
        self.ledger.grant('a', 'voice_verification', 'n', 365)
        self.ledger.grant('b', 'voice_verification', 'n', 365)
        self.vault.store('a', EMB)
        self.clock.t += 20 * DAY
        self.vault.store('b', EMB)
        self.clock.t += 15 * DAY
        self.assertEqual(self.vault.purge_expired(), 1)
        self.assertEqual(self.vault.load('b'), EMB)

    def test_no_plaintext_or_raw_id_on_disk(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        self.vault.db.commit()
        for f in self.dir.glob('*.db'):
            data = f.read_bytes()
            self.assertNotIn(b'alice@example.com', data)
            self.assertNotIn(EMB, data)

    def test_ciphertext_swap_between_subjects_fails(self):
        self.consent('a')
        self.consent('b')
        self.vault.store('a', EMB)
        self.vault.store('b', EMB[::-1])
        sa, sb = self.ledger.subject('a'), self.ledger.subject('b')
        nb, bb, _ = self.vault.db.execute('SELECT nonce,blob,created FROM template WHERE subject=?', (sb,)).fetchone()
        self.vault.db.execute('UPDATE template SET nonce=?, blob=? WHERE subject=?', (nb, bb, sa))
        with self.assertRaises(ConsentError):
            self.vault.load('a')

    def test_bit_flip_detected(self):
        self.consent()
        self.vault.store('alice@example.com', EMB)
        sub = self.ledger.subject('alice@example.com')
        blob = bytearray(self.vault.db.execute('SELECT blob FROM template WHERE subject=?', (sub,)).fetchone()[0])
        blob[0] ^= 1
        self.vault.db.execute('UPDATE template SET blob=? WHERE subject=?', (bytes(blob), sub))
        with self.assertRaises(ConsentError):
            self.vault.load('alice@example.com')

    def test_history_has_no_biometric_content(self):
        self.consent()
        self.ledger.withdraw('alice@example.com')
        h = self.ledger.history('alice@example.com')
        self.assertEqual(len(h), 1)
        self.assertIsNotNone(h[0]['withdrawn'])

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            self.ledger.subject('')
        self.consent()
        with self.assertRaises(ValueError):
            self.vault.store('alice@example.com', b'')


if __name__ == '__main__':
    unittest.main()
