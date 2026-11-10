import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from voice_command import parse_payment
from research_ui import ResearchVoice
from seven_flow import Flow
from contacts import add_contact, CONTACTS

class VoiceV9(unittest.TestCase):
    def test_common_payment_phrases(self):
        for text in ('pay to Chandu 5000', 'send Chandu rupees 5000',
                     'transfer to Chandu five thousand rupees', 'pay Chandu rs. 5000'):
            with self.subTest(text=text):
                self.assertEqual(parse_payment(text), ('Chandu', '5000.00'))

    def test_ambiguous_commands_still_rejected(self):
        for text in ('pay Chandu 5000 k', 'send Chandu 5000 and Priya 1000',
                     'pay to Chandu minus 5000', 'pay Chandu 0', 'pay Chandu 50001'):
            with self.subTest(text=text), self.assertRaises(ValueError): parse_payment(text)

    def test_new_recipient_continues_review_without_starting_flow(self):
        obj=SimpleNamespace(add_recipient=Mock(),resume_recipient=Mock())
        ResearchVoice.choose_recipient(obj,'New Person Vnine','5000.00')
        args=obj.add_recipient.call_args.args
        self.assertEqual(args[0],'New Person Vnine')
        c=SimpleNamespace(name='New Person Vnine')
        args[1](c)
        obj.resume_recipient.assert_called_once_with(c,'5000.00')

    def test_resume_preserves_amount_and_opens_review(self):
        obj=SimpleNamespace(amt=Mock(),choose_recipient=Mock())
        ResearchVoice.resume_recipient(obj,SimpleNamespace(name='Chandu'),'5000.00')
        obj.amt.insert.assert_called_once_with(0,'5000.00')
        obj.choose_recipient.assert_called_once_with('Chandu','5000.00')

    def test_spoken_command_through_seven_demo_gates(self):
        contact=add_contact('Vnine Tester','1234','vnine@demo',persist=False)
        try:
            name,amount=parse_payment('send to Vnine Tester five thousand rupees')
            f=Flow(); before=f.lab.balance
            f.start(name,amount,contact.id)
            f.scenario(0,True); f.verify_pin('246810'); f.verify_otp(f.issue_otp())
            for stage in (3,4,5,6): f.scenario(stage,True)
            f.encrypt(); result=f.confirm()
            self.assertEqual(f.stage,8);self.assertEqual(f.lab.balance,before-500000)
            self.assertEqual(result['payment_id'],'vnine@demo')
            with self.assertRaises(ValueError): f.confirm()
        finally: CONTACTS.remove(contact)
