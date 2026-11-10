import unittest
from cryptography.exceptions import InvalidTag
from core import Lab, tampered

class Tests(unittest.TestCase):
    def test_roundtrip(self):
        lab = Lab(); packet, intent, _ = lab.prepare('Priya','5000')
        self.assertEqual(len(packet.kem),1088)
        self.assertEqual(lab.confirm(packet),intent)
        self.assertEqual(lab.balance,4500000)
    def test_tamper(self):
        lab = Lab(); packet, _, _ = lab.prepare('Priya','5000')
        with self.assertRaises(InvalidTag): lab.confirm(tampered(packet))
        self.assertEqual(lab.balance,5000000)
    def test_replay(self):
        lab = Lab(); packet, _, _ = lab.prepare('Priya','5000'); lab.confirm(packet)
        with self.assertRaises(ValueError): lab.confirm(packet)
    def test_expiry(self):
        lab = Lab(); packet, intent, _ = lab.prepare('Priya','5000')
        raw, _ = lab.pending[intent['id']]; lab.pending[intent['id']] = (raw,0)
        with self.assertRaises(ValueError): lab.confirm(packet)
    def test_invalid_amounts(self):
        for amount in ['0','-1','NaN','Infinity','1.001','50001','abc']:
            with self.subTest(amount=amount), self.assertRaises(ValueError): Lab().prepare('Priya',amount)
    def test_wrong_key(self):
        lab = Lab(); packet, _, _ = lab.prepare('Priya','5000')
        with self.assertRaises(InvalidTag): Lab().confirm(packet)
    def test_quantum_simulator(self):
        from quantum_experiment import simulate
        counts = simulate()
        self.assertEqual(sum(counts.values()),1024)
        self.assertTrue(set(counts).issubset({'00','11'}))

if __name__ == '__main__': unittest.main()
