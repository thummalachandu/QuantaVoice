import unittest
from array import array
from audio_check import levels

class AudioLevels(unittest.TestCase):
    def test_silence(self):
        self.assertEqual(levels(array('h',[0]*1600).tobytes()),(-120.,0.))
    def test_level(self):
        db,clip=levels(array('h',[16384,-16384]*800).tobytes())
        self.assertAlmostEqual(db,-6.0206,places=3)
        self.assertEqual(clip,0)
    def test_clipping(self):
        _,clip=levels(array('h',[32767,-32768]*800).tobytes())
        self.assertEqual(clip,1.)

if __name__=='__main__': unittest.main()
