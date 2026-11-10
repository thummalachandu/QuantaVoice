"""Server-issued one-time spoken challenge: defeats replay of recorded audio and pre-made clones.

The speaker must say fresh random digits within a short window. Expected digits are bound to one
transaction digest and are consumed on first use. A real-time voice clone could still read them,
so this is one layer next to speaker verification and anti-spoofing, never a replacement.
"""
import hashlib
import hmac
import re
import secrets
import threading
import time
import unicodedata

DIGIT_WORDS = {
    'en': 'zero one two three four five six seven eight nine'.split(),
    'es': 'cero uno dos tres cuatro cinco seis siete ocho nueve'.split(),
    'de': 'null eins zwei drei vier fünf sechs sieben acht neun'.split(),
    'ko': '영 일 이 삼 사 오 육 칠 팔 구'.split(),
    'hi': 'शून्य एक दो तीन चार पाँच छह सात आठ नौ'.split(),
    'te': 'సున్నా ఒకటి రెండు మూడు నాలుగు ఐదు ఆరు ఏడు ఎనిమిది తొమ్మిది'.split(),
}


def _norm(text):
    return unicodedata.normalize('NFC', text).lower()


class ChallengeService:
    def __init__(self, ttl=45, length=6, clock=time.monotonic):
        if not 4 <= length <= 10:
            raise ValueError('Challenge length must be 4 to 10 digits.')
        self.ttl, self.length, self.clock = ttl, length, clock
        self.lock = threading.Lock()
        self.active = {}

    def issue(self, intent_digest, lang='en'):
        if lang not in DIGIT_WORDS:
            raise ValueError('Unsupported challenge language.')
        digits = ''.join(str(secrets.randbelow(10)) for _ in range(self.length))
        while len(set(digits)) < 3:  # avoid trivial 000000 / 111111 patterns
            digits = ''.join(str(secrets.randbelow(10)) for _ in range(self.length))
        cid = secrets.token_hex(12)
        with self.lock:
            now = self.clock()
            self.active = {k: v for k, v in self.active.items() if v['exp'] > now}
            self.active[cid] = {'digits': digits, 'digest': intent_digest, 'lang': lang, 'exp': now + self.ttl}
        return {'challenge_id': cid, 'digits': digits, 'lang': lang, 'expires_in': self.ttl,
                'spoken_form': ' '.join(_norm(DIGIT_WORDS[lang][int(d)]) for d in digits)}

    @staticmethod
    def transcript_to_digits(transcript, lang):
        words = {_norm(w): str(i) for i, w in enumerate(DIGIT_WORDS[lang])}
        out = []
        if lang == 'ko': words['공'] = '0'  # both 영 and 공 are spoken for zero
        for tok in (t for t in re.split(r'[\s,.;:!?।\-]+', _norm(transcript)) if t):  # \w would split Indic combining marks
            if tok.isdigit():
                out.append(tok)
            elif tok in words:
                out.append(words[tok])
            elif lang == 'ko' and all(ch in words for ch in tok):  # Whisper may join syllables: 일이삼
                out.extend(words[ch] for ch in tok)
            else:
                return None  # any unknown word invalidates the attempt
        return ''.join(out)

    def verify(self, challenge_id, intent_digest, transcript):
        """One attempt only: the challenge is consumed whether it succeeds or not."""
        with self.lock:
            item = self.active.pop(challenge_id, None)
        if not item or self.clock() >= item['exp']:
            return False
        if not hmac.compare_digest(item['digest'], intent_digest):
            return False
        heard = self.transcript_to_digits(transcript, item['lang'])
        return heard is not None and hmac.compare_digest(heard, item['digits'])
