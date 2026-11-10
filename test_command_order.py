import unittest
from voice_command import parse_payment
class CommandOrder(unittest.TestCase):
    def test_name_first_numeric(self):
        self.assertEqual(parse_payment('pay Chandu 5000'),('Chandu','5000.00'))
        self.assertEqual(parse_payment('Send Tummala Chandu 5,000 rupees'),('Tummala Chandu','5000.00'))
        self.assertEqual(parse_payment('pay Chandu 5000 rupee'),('Chandu','5000.00'))
    def test_name_first_words(self):
        self.assertEqual(parse_payment('pay Chandu five thousand'),('Chandu','5000.00'))
    def test_amount_first_unchanged(self):
        self.assertEqual(parse_payment('pay 5000 rupees to Chandu'),('Chandu','5000.00'))
        self.assertEqual(parse_payment('pay 5000 rupee to chandu'),('chandu','5000.00'))
        self.assertEqual(parse_payment('send five thousand rupees to Chandu'),('Chandu','5000.00'))
    def test_ambiguous_and_unrelated(self):
        for t in ['pay Chandu 5000 k','my nose then','we can do fine','play Chandu 5000','pay Chandu 5000 and pay Priya 200']:
            with self.subTest(t=t),self.assertRaises(ValueError): parse_payment(t)
