import unittest
from voice_command import parse_payment

class VoiceCommands(unittest.TestCase):
    def test_commands(self):
        examples={
            'Pay five thousand rupees to Priya':('Priya','5000.00'),
            'send two thousand to Rahul':('Rahul','2000.00'),
            'Transfer one thousand five hundred to Sneha':('Sneha','1500.00'),
            'Pay five thousand and fifty to Amit':('Amit','5050.00'),
            'pay five hundred and twenty five to Ananya':('Ananya','525.00'),
            'pay 5,000.50 to Vikram':('Vikram','5000.50'),
            'pay rupees fifty to Priya.':('Priya','50.00')}
        for command,expected in examples.items():
            with self.subTest(command=command): self.assertEqual(parse_payment(command),expected)
    def test_reject_ambiguity(self):
        for command in ['pay five five to Priya','pay zero to Priya','pay -500 to Priya',
                        'pay fifty thousand one to Priya',
                        'pay 5000 to Priya and 2000 to Rahul','cancel pay 500 to Priya',
                        'pay one hundred and to Priya','pay one thousand and to Priya',
                        'pay 1,00 to Priya','pay 5.001 to Priya','pay five or six to Priya']:
            with self.subTest(command=command),self.assertRaises(ValueError): parse_payment(command)
    def test_parsed_intent_encryption(self):
        from seven_flow import Flow
        recipient,amount=parse_payment('Pay five thousand rupees to Priya')
        f=Flow(); f.start(recipient,amount)
        self.assertEqual(f.recipient,'Priya'); self.assertEqual(f.amount,'5000.0')
        self.assertEqual(f.stage,0)  # Speech transcription must NOT mark voice identity as verified.
        with self.assertRaises(ValueError): f.encrypt()

if __name__=='__main__': unittest.main()
