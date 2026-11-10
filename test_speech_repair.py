import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
import numpy as np
from voice_command import parse_payment
from whisper_engine import WhisperRecognizer
from microphone import Microphone

class SpeechRepair(unittest.TestCase):
    def test_polite_phrases(self):
        for phrase in ['please pay Chandu five thousand rupees',
                       'could you please send 5000 rupees to Chandu',
                       'pay Chandu ₹5000', 'pay INR 5000 to Chandu',
                       'pay Chandu five thousand, please', 'Pay Chandu, 5000.']:
            with self.subTest(phrase=phrase):
                self.assertEqual(parse_payment(phrase), ('Chandu','5000.00'))

    def test_hyphenated_amount_preserves_name(self):
        self.assertEqual(parse_payment('please pay Mary-Jane twenty-five rupees'), ('Mary-Jane','25.00'))

    def test_negation_and_multiple_commands_blocked(self):
        for phrase in ['do not pay Chandu 5000', 'please do not pay Chandu 5000',
                       'please pay Chandu 5000 then pay Priya 100',
                       'cancel pay Chandu 5000', 'please pay Chandu minus 5000']:
            with self.subTest(phrase=phrase), self.assertRaises(ValueError):
                parse_payment(phrase)

    def test_whisper_resampling_and_options(self):
        word=SimpleNamespace(word='Chandu',probability=.8)
        model=Mock()
        model.transcribe.return_value=(iter([SimpleNamespace(text=' Pay Chandu 5000.', words=[word])]),None)
        rec=WhisperRecognizer(model,'en',48000)
        self.assertFalse(rec.AcceptWaveform(np.zeros(48000,dtype=np.int16).tobytes()))
        self.assertEqual(json.loads(rec.PartialResult())['partial'],'')
        result=json.loads(rec.FinalResult())
        self.assertEqual(result['text'],'Pay Chandu 5000.')
        self.assertEqual(result['result'][0]['conf'],.8)
        args,kwargs=model.transcribe.call_args
        self.assertEqual(len(args[0]),16000)
        self.assertTrue(kwargs['vad_filter'])
        self.assertFalse(kwargs['condition_on_previous_text'])
        self.assertNotIn('initial_prompt',kwargs)
        self.assertEqual(rec.chunks,[])

    def test_playback_before_recording_is_safe(self):
        self.assertIsNone(Microphone().last_audio)

class RecordingPipeline(unittest.TestCase):
    def exercise_capture(self, fail=False):
        import sys
        from pathlib import Path
        from unittest.mock import patch
        mic=Microphone()
        rec=Mock()
        def accept(data):
            mic.stop()
            return False
        rec.AcceptWaveform.side_effect=accept
        rec.PartialResult.return_value='{"partial":""}'
        if fail:
            rec.FinalResult.side_effect=RuntimeError('decoder failed')
        else:
            rec.FinalResult.return_value='{"text":"please pay Chandu 5000","result":[{"conf":0.4}]}'
        class Stream:
            def __init__(self, **kw): self.callback=kw['callback']
            def __enter__(self):
                self.callback(np.full(32000,1000,dtype=np.int16).tobytes(),32000,None,None)
            def __exit__(self,*args): pass
        sd=SimpleNamespace(query_devices=lambda *a:{'default_samplerate':16000,'name':'test input'},RawInputStream=Stream)
        with patch.dict(sys.modules,{'sounddevice':sd}), patch('whisper_engine.make_recognizer',return_value=rec):
            mic._record(None,Path('whisper-en'))
        events=[]
        while not mic.events.empty(): events.append(mic.events.get_nowait())
        return mic,events

    def test_capture_decode_and_low_confidence(self):
        mic,events=self.exercise_capture()
        self.assertEqual(len(mic.last_audio[0]),64000)
        self.assertIn(('transcript','please pay Chandu 5000'),events)
        self.assertTrue(any(k=='quality' and 'confidence' in v for k,v in events))
        self.assertEqual(events[-1],('finished',''))

    def test_decoder_failure_keeps_audio_and_diagnostics(self):
        mic,events=self.exercise_capture(True)
        self.assertIsNotNone(mic.last_audio)
        self.assertTrue(any(k=='diagnostic' for k,v in events))
        self.assertIn(('error','decoder failed'),events)
        self.assertFalse(any(k=='transcript' for k,v in events))
        self.assertEqual(events[-1],('finished',''))
