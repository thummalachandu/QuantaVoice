"""Local Whisper adapter. Setup downloads weights; inference never uploads audio."""
import json
import math
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent / 'models' / 'faster-whisper-small'


def setup():
    from faster_whisper.utils import download_model
    MODEL_DIR.parent.mkdir(parents=True, exist_ok=True)
    print('Downloading multilingual Whisper small (roughly 500 MB). First setup only.', flush=True)
    download_model('small', output_dir=str(MODEL_DIR))
    # Load once so incomplete or incompatible installations fail during setup.
    from faster_whisper import WhisperModel
    WhisperModel(str(MODEL_DIR), device='cpu', compute_type='int8', local_files_only=True)
    (MODEL_DIR/'setup-complete.txt').write_text('small; cpu int8; faster-whisper 1.2.1',encoding='utf-8')
    print('Whisper ready. Subsequent transcription runs locally.', flush=True)


def make_recognizer(microphone, language, sample_rate):
    if language not in ('en', 'hi', 'te', 'es', 'de', 'ko'):
        raise ValueError('Unsupported command language.')
    if not (MODEL_DIR / 'model.bin').is_file():
        raise RuntimeError('Whisper model missing. Run START_QUANTAVOICE.cmd with internet once.')
    try:
        from faster_whisper import WhisperModel
    except ImportError as exc:
        raise RuntimeError('Whisper dependency missing. Run START_QUANTAVOICE.cmd.') from exc
    if getattr(microphone, 'whisper_model', None) is None:
        microphone.whisper_model = WhisperModel(str(MODEL_DIR), device='cpu', compute_type='int8', local_files_only=True)
    return WhisperRecognizer(microphone.whisper_model, language, sample_rate)


class WhisperRecognizer:
    """Match the streaming interface; decode once after capture has stopped."""
    def __init__(self, model, language, rate):
        self.model, self.language, self.rate = model, language, rate
        self.chunks = []

    def AcceptWaveform(self, data):
        self.chunks.append(data)
        return False

    def PartialResult(self):
        return json.dumps({'partial': ''})

    def FinalResult(self):
        import numpy as np
        from scipy.signal import resample_poly
        audio = np.frombuffer(b''.join(self.chunks), dtype=np.int16).astype(np.float32) / 32768.0
        self.chunks.clear()
        if self.rate != 16000:
            divisor = math.gcd(self.rate, 16000)
            audio = resample_poly(audio, 16000 // divisor, self.rate // divisor).astype(np.float32)
        # No example payment/amount in a prompt: avoid encouraging an invented command.
        segments, _ = self.model.transcribe(audio, language=self.language, beam_size=5,
            vad_filter=True, condition_on_previous_text=False, temperature=0,
            word_timestamps=True)
        texts, words = [], []
        for segment in segments:
            texts.append(segment.text.strip())
            for word in segment.words or []:
                words.append({'word': word.word.strip(), 'conf': float(word.probability)})
        return json.dumps({'text': ' '.join(texts).strip(), 'result': words})
