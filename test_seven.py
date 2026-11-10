import unittest
from cryptography.exceptions import InvalidTag
from seven_flow import Flow

def ready():
    f=Flow(); f.start('Priya','5000'); f.scenario(0,True)
    f.verify_pin('246810'); code=f.issue_otp(); f.verify_otp(code)
    for stage in (3,4,5,6): f.scenario(stage,True)
    return f

class SevenTests(unittest.TestCase):
    def test_all_layers_and_payment(self):
        f=ready(); self.assertEqual(f.stage,7); f.encrypt(); f.confirm()
        self.assertEqual(f.lab.balance,4500000)
        with self.assertRaises(ValueError): f.confirm()
    def test_no_skip(self):
        f=Flow(); f.start('Priya','5000')
        with self.assertRaises(ValueError): f.encrypt()
        with self.assertRaises(ValueError): f.scenario(6,True)
    def test_each_simulated_rejection_blocks(self):
        for target in (0,3,4,5,6):
            f=Flow(); f.start('Priya','5000')
            if target:
                f.scenario(0,True); f.verify_pin('246810'); f.verify_otp(f.issue_otp())
                for step in range(3,target): f.scenario(step,True)
            with self.assertRaises(ValueError): f.scenario(target,False)
            with self.assertRaises(ValueError): f.encrypt()
            self.assertEqual(f.lab.balance,5000000)
    def test_pin_lockout(self):
        f=Flow(); f.start('Priya','5000'); f.scenario(0,True)
        for _ in range(3):
            with self.assertRaises(ValueError): f.verify_pin('wrong')
        with self.assertRaises(ValueError): f.verify_pin('246810')
    def test_otp_expiry_and_lockout(self):
        f=Flow(); f.start('Priya','5000'); f.scenario(0,True); f.verify_pin('246810')
        code=f.issue_otp(); f.otp_deadline=0
        with self.assertRaises(ValueError): f.verify_otp(code)
        for _ in range(3):
            f.issue_otp()
            with self.assertRaises(ValueError): f.verify_otp('invalid')
        self.assertTrue(f.blocked)
    def test_tamper_preserves_balance(self):
        f=ready(); f.encrypt()
        with self.assertRaises(InvalidTag): f.tamper()
        self.assertEqual(f.lab.balance,5000000); f.confirm()
    def test_restart_invalidates_gates(self):
        f=ready(); f.encrypt(); f.start('Rahul','2000')
        self.assertIsNone(f.packet)
        with self.assertRaises(ValueError): f.confirm()

if __name__=='__main__': unittest.main()
