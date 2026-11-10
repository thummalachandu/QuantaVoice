import json
import math
import tempfile
import unittest
from pathlib import Path

import evidence

CFG = {'asv_threshold': 0.4, 'cm_threshold': 1.5, 'thresholds_from_dev': True}
SCORES = lambda asv, cm: {'asv': asv, 'cm': cm, 'asv_ms': 1.0, 'cm_ms': 1.0}


class Mapping(unittest.TestCase):
    def test_threshold_maps_to_exactly_half(self):
        for t in (-0.9, -0.2, 0.0, 0.4, 0.95):
            self.assertEqual(evidence.asv_to_unit(t, t), 0.5)
        for t in (-20.0, -1.5, 0.0, 3.0, 17.25):
            self.assertEqual(evidence.cm_to_unit(t, t), 0.5)

    def test_monotone_and_bounded(self):
        xs = [i / 50 - 1 for i in range(101)]
        a = [evidence.asv_to_unit(x, 0.4) for x in xs]
        self.assertEqual(a, sorted(a)); self.assertTrue(all(0 <= v <= 1 for v in a))
        ys = [i / 4 - 30 for i in range(241)]
        c = [evidence.cm_to_unit(y, 1.5) for y in ys]
        self.assertEqual(c, sorted(c)); self.assertTrue(all(0 <= v <= 1 for v in c))

    def test_extreme_values_do_not_overflow(self):
        self.assertGreater(evidence.cm_to_unit(1e9, 0), 0.999)
        self.assertLess(evidence.cm_to_unit(-1e9, 0), 0.001)
        self.assertEqual(evidence.asv_to_unit(5, 0.4), 1.0)  # clamped to the cosine range
        self.assertEqual(evidence.asv_to_unit(-5, 0.4), 0.0)

    def test_pass_fail_identical_to_harness_rule(self):
        # The engine cuts at 0.5 (strict <), the harness passes on >=. They must agree everywhere.
        for asv in (-0.5, 0.39999, 0.4, 0.40001, 0.9):
            for cm in (-3.0, 1.4999, 1.5, 1.5001, 8.0):
                out = evidence.voice_scores(SCORES(asv, cm), CFG)
                self.assertEqual(out['asv_score'] >= 0.5, asv >= 0.4, (asv, cm))
                self.assertEqual(out['cm_score'] >= 0.5, cm >= 1.5, (asv, cm))

    def test_borderline_fail_is_never_rounded_up_to_pass(self):
        # Regression: a score 1e-7 below threshold used to be rounded to 0.5, which the engine passes.
        for eps in (1e-7, 1e-9, 1e-12):
            out = evidence.voice_scores(SCORES(0.4 - eps, 1.5 - eps), CFG)
            self.assertLess(out['asv_score'], 0.5, eps)
            self.assertLess(out['cm_score'], 0.5, eps)
            self.assertFalse(out['asv_score'] >= 0.5)
            self.assertFalse(out['cm_score'] >= 0.5)
        out = evidence.voice_scores(SCORES(0.4 + 1e-9, 1.5 + 1e-9), CFG)
        self.assertGreaterEqual(out['asv_score'], 0.5)
        self.assertGreaterEqual(out['cm_score'], 0.5)

    def test_risk_engine_agrees_with_harness_decision(self):
        from risk_engine import RiskEngine
        r = RiskEngine()
        base = {'new_payee': False, 'device_bound': True, 'challenge_verified': True}
        for asv, cm, passed in ((0.5, 2.0, True), (0.39, 2.0, False), (0.5, 1.4, False)):
            ctx = dict(base, **evidence.voice_scores(SCORES(asv, cm), CFG))
            action = r.evaluate(100000, 'u', ctx).action
            self.assertEqual(action == 'allow', passed, (asv, cm, action))

    def test_rejects_non_measured_or_nonfinite(self):
        for bad in ({'asv': 0.9, 'cm': 3.0}, {}, None, 'x', {'asv': 0.9, 'cm': 3.0, 'passed': True}):
            with self.assertRaises(ValueError): evidence.voice_scores(bad, CFG)
        with self.assertRaises(ValueError): evidence.voice_scores(SCORES(math.nan, 1), CFG)
        with self.assertRaises(ValueError): evidence.voice_scores(SCORES(0.5, math.inf), CFG)
        with self.assertRaises(ValueError): evidence.asv_to_unit(0.5, 1.0)

    def test_context_has_only_verified_fields(self):
        ctx = evidence.build_context()
        self.assertEqual(ctx, {'channel': 'app'})
        ctx = evidence.build_context(evidence.voice_scores(SCORES(0.9, 4), CFG), device_verified=True, channel='telephone', hour=13)
        self.assertEqual(set(ctx), {'channel', 'asv_score', 'cm_score', 'device_bound', 'hour'})
        for truthy in (1, 'yes', 'True', [1]):  # only the real boolean True counts
            self.assertNotIn('device_bound', evidence.build_context(device_verified=truthy))
        self.assertNotIn('challenge_verified', ctx)

    def test_channel_for(self):
        self.assertEqual(evidence.channel_for({'live_channel': 'ulaw'}), 'telephone')
        self.assertEqual(evidence.channel_for({'live_channel': 'clean16'}), 'app')
        self.assertEqual(evidence.channel_for(None), 'app')


class Config(unittest.TestCase):
    def write(self, data):
        d = tempfile.mkdtemp(); p = Path(d) / 'c.json'; p.write_text(json.dumps(data)); return p

    def test_loads_calibrated_config(self):
        self.assertEqual(evidence.load_config(self.write(CFG))['cm_threshold'], 1.5)

    def test_refuses_uncalibrated_or_bad(self):
        for bad in (dict(CFG, thresholds_from_dev=False), {'asv_threshold': 0.4}, dict(CFG, asv_threshold=1.5),
                    dict(CFG, cm_threshold=float('nan')), dict(CFG, thresholds_from_dev='true')):
            with self.assertRaises(ValueError): evidence.load_config(self.write(bad))
        with self.assertRaises(ValueError): evidence.load_config(Path(tempfile.mkdtemp()) / 'missing.json')

    def test_documented_location(self):
        self.assertEqual(evidence.config_path().name, 'research_config.json')
        self.assertEqual(evidence.config_path().parent.name, 'QuantaVoice_Data')


if __name__ == '__main__':
    unittest.main()
