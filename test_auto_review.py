import unittest,queue
from types import SimpleNamespace
from live_voice import LiveVoice
class Value:
    def __init__(self,v=''): self.v=v
    def get(self): return self.v
    def set(self,v): self.v=v
class AutoReview(unittest.TestCase):
    def fake(self,events):
        q=queue.Queue()
        for e in events:q.put(e)
        obj=SimpleNamespace(closing=False,active=True,mic=SimpleNamespace(events=q),status=Value(),transcript=Value(),signal=Value(),auto_review=Value(True),final_command='',capture_warning='',reviews=0,root=SimpleNamespace(after=lambda *a:None),write=lambda *a:None,controls_idle=lambda:None)
        def review():
            self.assertFalse(obj.active)
            obj.reviews+=1
        obj.poll=lambda:LiveVoice.poll(obj)
        obj.review=review
        obj.finish_command=lambda:LiveVoice.finish_command(obj)
        return obj
    def test_clear_speech_opens_one_review_after_stop(self):
        o=self.fake([('transcript','pay Chandu 5000'),('finished',''),('finished','')]);LiveVoice.poll(o);self.assertEqual(o.reviews,1)
    def test_low_confidence_requires_correction(self):
        o=self.fake([('transcript','pay Chandu 5000'),('quality','Low confidence'),('finished','')]);LiveVoice.poll(o);self.assertEqual(o.reviews,0);self.assertIn('Correct',o.status.get())
    def test_unrelated_speech_never_opens_review(self):
        o=self.fake([('transcript','they can do by now'),('finished','')]);LiveVoice.poll(o);self.assertEqual(o.reviews,0)
    def test_recording_error_clears_result(self):
        o=self.fake([('transcript','pay Chandu 5000'),('error','overflow'),('finished','')]);LiveVoice.poll(o);self.assertEqual(o.reviews,0);self.assertEqual(o.transcript.get(),'')
    def test_manual_mode_does_not_open_review(self):
        o=self.fake([('transcript','pay Chandu 5000'),('finished','')]);o.auto_review.set(False);LiveVoice.poll(o);self.assertEqual(o.reviews,0)
