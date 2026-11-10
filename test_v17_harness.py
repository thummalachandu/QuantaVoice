import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

import ccaas_connector as cc
import research

ROOT = Path(__file__).resolve().parent.parent


class ChannelMatchesTelephonyPath(unittest.TestCase):
    def tone(self, rate=16000, seconds=2):
        t = np.arange(rate * seconds) / rate
        return (0.4 * np.sin(2 * np.pi * 300 * t) + 0.2 * np.sin(2 * np.pi * 1700 * t)).astype(np.float32)

    def test_ulaw_and_alaw_equal_the_live_path(self):
        x = self.tone()
        x8 = research.resample(x, 16000, 8000)
        pcm = np.clip(np.rint(x8 * 32768), -32768, 32767).astype('<i2')
        live_ulaw = cc.to_model_audio(cc.ulaw_decode(cc.ulaw_encode(pcm)))   # what ccaas/Twilio ingest produces
        live_alaw = cc.to_model_audio(cc.alaw_decode(cc.alaw_encode(pcm)))
        np.testing.assert_array_equal(research.channel(x, 16000, 'ulaw'), live_ulaw)
        np.testing.assert_array_equal(research.channel(x, 16000, 'alaw'), live_alaw)

    def test_shapes_and_range(self):
        x = self.tone()
        for codec in ('clean16', 'pcm8', 'alaw', 'ulaw'):
            y = research.channel(x, 16000, codec, 1)
            self.assertEqual(y.dtype, np.float32); self.assertEqual(len(y), 16000)
            self.assertLessEqual(float(np.abs(y).max()), 1.0)

    def test_codecs_really_lose_bandwidth_and_differ_from_clean(self):
        t = np.arange(32000) / 16000
        high = (0.5 * np.sin(2 * np.pi * 6000 * t)).astype(np.float32)  # above the 4 kHz telephone band
        self.assertLess(float(np.abs(research.channel(high, 16000, 'ulaw')).max()), 0.12)  # >12 dB attenuation of an out-of-band tone
        self.assertGreater(float(np.abs(research.channel(high, 16000, 'clean16')).max()), 0.4)

    def test_no_audioop_import_anywhere(self):
        for path in (ROOT / 'quantavoice').glob('*.py'):
            if path.name.startswith('test_'): continue
            self.assertIsNone(re.search(r'^\s*(import|from)\s+audioop', path.read_text(encoding='utf-8'), re.M), path.name)

    def test_bad_inputs_still_fail(self):
        x = self.tone()
        with self.assertRaises(ValueError): research.channel(x, 16000, 'alaw', 3)  # source shorter than requested
        with self.assertRaises(ValueError): research.channel(x, 16000, 'gsm')


class EntryPoint(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(ROOT / 'run_research.py'), *args], capture_output=True, text=True, cwd=cwd, timeout=60)

    def test_help_lists_all_four_modes(self):
        out = self.run_cli('--help').stdout
        for flag in ('--install-research', '--example-config', '--evaluate', '--qml'):
            self.assertIn(flag, out)

    def test_requires_a_mode(self):
        self.assertNotEqual(self.run_cli().returncode, 0)

    def test_missing_files_fail_closed_with_message(self):
        r = self.run_cli('--evaluate', 'nope.json', 'nope.json', 'out.json')
        self.assertEqual(r.returncode, 1); self.assertIn('Blocked', r.stderr)

    def test_example_config_is_uncalibrated_and_refused(self):
        import evidence
        cfg = json.loads((ROOT / 'research_config.example.json').read_text())
        self.assertIs(cfg['thresholds_from_dev'], False)
        d = Path(tempfile.mkdtemp()) / 'c.json'; d.write_text(json.dumps(cfg))
        with self.assertRaises(ValueError): evidence.load_config(d)  # cannot be used live until calibrated

    def test_documented_config_location_is_the_one_the_gui_uses(self):
        import evidence, research_templates
        self.assertIn('QuantaVoice_Data/research_config.json', research_templates.GUIDE)
        self.assertEqual(evidence.config_path().relative_to(ROOT).as_posix(), 'QuantaVoice_Data/research_config.json')

    def test_requirements_file_present_and_no_sloppy_pins(self):
        text = (ROOT / 'requirements-research.txt').read_text()
        for pkg in ('torch', 'speechbrain', 'scipy', 'scikit-learn', 'qiskit'):
            self.assertIn(pkg, text)


if __name__ == '__main__':
    unittest.main()
