import unittest
from voice_command import parse_payment
from research_ui import ResearchVoice
from unittest.mock import Mock
from types import SimpleNamespace

class VoiceV10(unittest.TestCase):
    def test_spoken_paise(self):
        for phrase,amount in [('pay Chandu five thousand point five zero','5000.50'),('pay zero point five to Chandu','0.50')]:
            self.assertEqual(parse_payment(phrase),('Chandu',amount))
    def test_ambiguous_decimals_blocked(self):
        for phrase in ['pay Chandu five point fifty','pay Chandu five point one two three','pay Chandu five point one point two','pay Chandu fifty thousand point one']:
            with self.subTest(phrase=phrase),self.assertRaises(ValueError): parse_payment(phrase)
    def test_demo_selection_explicit(self):
        obj=SimpleNamespace(presentation=Mock(),mode_changed=Mock(),status=Mock())
        ResearchVoice.enable_demo(obj)
        obj.presentation.set.assert_called_once_with(True)
        obj.mode_changed.assert_called_once()
