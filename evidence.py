"""Turn MEASURED model scores into the API's 0-1 `context`, never anything else.

Raw ECAPA output is a cosine in [-1, 1]; AASIST output is an unbounded logit margin. The API wants
0-1 and the risk engine cuts at 0.5, so each score is mapped monotonically so that the
development-calibrated threshold lands on EXACTLY 0.5. The 0-1 value is a re-scaling for the
engine, not a probability and not a confidence.

Rules this module enforces:
* Only real model scores (asv/cm from live inference) are converted. Presentation-mode buttons such
  as "Genuine speaker scenario" produce no evidence at all.
* `device_bound` is true only when the app itself verified a WebAuthn assertion.
* `challenge_verified` is NEVER produced here; only the API can establish it.
"""
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'QuantaVoice_Data'


def config_path():
    """The single documented location (matches the research guide)."""
    return DATA / 'research_config.json'


def load_config(path=None):
    path = Path(path) if path else config_path()
    try:
        config = json.loads(path.read_text(encoding='utf-8'))
    except OSError as exc:
        raise ValueError('Research config not found at %s. Copy research_config.example.json there and calibrate it.' % path) from exc
    for k in ('asv_threshold', 'cm_threshold', 'thresholds_from_dev'):
        if k not in config:
            raise ValueError('Calibrate thresholds on a separate development set; config missing ' + k)
    if config['thresholds_from_dev'] is not True:
        raise ValueError('Development-set threshold calibration must be recorded first.')
    for k in ('asv_threshold', 'cm_threshold'):
        if isinstance(config[k], bool) or not math.isfinite(float(config[k])):
            raise ValueError('Thresholds must be finite numbers.')
    if not -1.0 < float(config['asv_threshold']) < 1.0:
        raise ValueError('asv_threshold must be strictly between -1 and 1 (cosine scale).')
    return config


def asv_to_unit(cosine, threshold):
    """Piecewise-linear on [-1, 1]; threshold -> 0.5; monotone and strictly inside [0, 1]."""
    x, t = float(cosine), float(threshold)
    if not math.isfinite(x) or not -1.0 < t < 1.0:
        raise ValueError('Invalid ASV score or threshold.')
    x = max(-1.0, min(1.0, x))
    return 0.5 * (x + 1.0) / (t + 1.0) if x <= t else 0.5 + 0.5 * (x - t) / (1.0 - t)


def cm_to_unit(logit, threshold):
    """Logistic around the CM threshold: 0.5 at the threshold, saturating without overflow."""
    x, t = float(logit), float(threshold)
    if not math.isfinite(x) or not math.isfinite(t):
        raise ValueError('Invalid CM score or threshold.')
    z = max(-40.0, min(40.0, x - t))
    return 1.0 / (1.0 + math.exp(-z))


def voice_scores(scores, config):
    """Measured scores -> {'asv_score','cm_score'}. Refuses anything not from real inference."""
    if not isinstance(scores, dict) or not {'asv', 'cm', 'asv_ms', 'cm_ms'} <= set(scores):
        raise ValueError('Voice evidence must come from live ASV + CM inference.')
    a = asv_to_unit(scores['asv'], config['asv_threshold'])
    c = cm_to_unit(scores['cm'], config['cm_threshold'])
    # Invariant the engine's decision rests on: same pass/fail as the research harness.
    # Checked on the exact values that are returned. Rounding is NOT applied: rounding a score
    # just below its threshold to 6 places can yield exactly 0.5, which the engine would pass.
    if (a >= 0.5) != (float(scores['asv']) >= float(config['asv_threshold'])) or \
            (c >= 0.5) != (float(scores['cm']) >= float(config['cm_threshold'])):
        raise ValueError('Score mapping disagrees with the calibrated threshold.')
    return {'asv_score': a, 'cm_score': c}


def build_context(voice=None, device_verified=False, channel='app', hour=None):
    """Assemble the API context from verified evidence only."""
    ctx = {'channel': channel}
    if voice:
        ctx.update({'asv_score': float(voice['asv_score']), 'cm_score': float(voice['cm_score'])})
    if device_verified is True:
        ctx['device_bound'] = True
    if hour is not None:
        ctx['hour'] = int(hour)
    assert 'challenge_verified' not in ctx
    return ctx


def channel_for(config):
    return 'telephone' if (config or {}).get('live_channel') in ('pcm8', 'alaw', 'ulaw') else 'app'
