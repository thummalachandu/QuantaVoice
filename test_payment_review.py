import unittest
from contacts import matches, resolve
from seven_flow import Flow
from core import tampered
from cryptography.exceptions import InvalidTag
from voice_command import parse_payment

class PaymentReview(unittest.TestCase):
    def ready(self, contact_id='demo-priya-2', note='Lunch'):
        f=Flow(); f.start('Priya','500',contact_id,note)
        f.scenario(0,True); f.verify_pin('246810'); f.verify_otp(f.issue_otp())
        for stage in (3,4,5,6): f.scenario(stage,True)
        return f

    def test_same_name_distinct_accounts(self):
        found=matches('Priya')
        self.assertEqual(len(found),2)
        self.assertNotEqual(found[0].payment_id,found[1].payment_id)
        with self.assertRaises(ValueError): resolve('Priya')

    def test_encrypted_destination_and_note(self):
        f=self.ready(); f.encrypt()
        with self.assertRaises(InvalidTag): f.lab.confirm(tampered(f.packet))
        result=f.confirm()
        self.assertEqual(result['payment_id'],'priya.work@demo')
        self.assertEqual(result['note'],'Lunch')
        self.assertEqual(f.lab.balance,4950000)
        with self.assertRaises(ValueError): f.confirm()

    def test_edit_requires_fresh_approvals(self):
        f=self.ready(); f.encrypt(); old=f.packet
        f.start('Priya','600','demo-priya-1','Changed')
        with self.assertRaises(ValueError): f.lab.confirm(old)
        with self.assertRaises(ValueError): f.encrypt()
        self.assertEqual(f.stage,0)

    def test_invalid_destination_note_and_unclear_voice(self):
        for name, cid, note in [('Rahul','demo-priya-1',''),('Priya','missing',''),('Priya','demo-priya-1','x'*141)]:
            with self.assertRaises(ValueError): Flow().start(name,'500',cid,note)
        with self.assertRaises(ValueError): parse_payment('be vital to can do')

    def test_face_rejection_cannot_be_bypassed(self):
        f=Flow(); f.start('Priya','500','demo-priya-1')
        f.scenario(0,True); f.verify_pin('246810'); f.verify_otp(f.issue_otp())
        with self.assertRaises(ValueError): f.scenario(3,False)
        with self.assertRaises(ValueError): f.scenario(4,True)
        with self.assertRaises(ValueError): f.encrypt()

if __name__=='__main__': unittest.main()
