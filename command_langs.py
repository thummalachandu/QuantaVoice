"""Spanish, German and Korean payment commands (To-Do B10, control C19).

Same rule as the English, Hindi and Telugu parser: strict, no fuzzy matching. One payment, one recipient, one amount.
Anything ambiguous raises ValueError and the app asks the user to repeat.

Number words: Spanish, German (including compound words such as 'fünftausendzweihundert') and Sino-Korean (오천, 이만 오천)
are parsed by exact grammar, not by guessing. Digits are also accepted. European digit grouping is handled explicitly
('5.000' means 5000, '5,50' means 5.50) and the unsafe forms ('5,000' in German or Spanish) are refused as ambiguous.

The wording of the example phrases and number tables was written by the author of this build, not reviewed by native
speakers. Have a native speaker check them before showing them to a customer.
"""
import re
import unicodedata

CUR_ES, CUR_DE, CUR_KO = r'(?:rupias?|rupees)', r'(?:rupien|rupie|rupees)', r'루피'


def _fold(text):
    """Lower-case and strip accents, so 'dieciséis' and 'dieciseis' read the same."""
    return ''.join(c for c in unicodedata.normalize('NFD', text.casefold()) if unicodedata.category(c) != 'Mn')


# ---------------------------------------------------------------- Spanish
_ES_UNITS = dict(zip('cero uno dos tres cuatro cinco seis siete ocho nueve'.split(), range(10)))
_ES_UNITS.update({'un': 1, 'una': 1})
_ES_TEENS = dict(zip('diez once doce trece catorce quince dieciseis diecisiete dieciocho diecinueve'.split(), range(10, 20)))
_ES_TWENTIES = dict(zip('veinte veintiuno veintiun veintidos veintitres veinticuatro veinticinco veintiseis veintisiete '
                        'veintiocho veintinueve'.split(), [20, 21, 21, 22, 23, 24, 25, 26, 27, 28, 29]))
_ES_TENS = dict(zip('treinta cuarenta cincuenta sesenta setenta ochenta noventa'.split(), range(30, 100, 10)))
_ES_HUND = {'ciento': 100, 'doscientos': 200, 'trescientos': 300, 'cuatrocientos': 400, 'quinientos': 500,
            'seiscientos': 600, 'setecientos': 700, 'ochocientos': 800, 'novecientos': 900}
ES_WORDS = set(_ES_UNITS) | set(_ES_TEENS) | set(_ES_TWENTIES) | set(_ES_TENS) | set(_ES_HUND) | {'cien', 'mil', 'y'}


def _es_under_100(t):
    if len(t) == 1:
        w = t[0]
        for table in (_ES_TEENS, _ES_TWENTIES, _ES_TENS):
            if w in table: return table[w]
        if w in _ES_UNITS and w != 'cero': return _ES_UNITS[w]
    if len(t) == 3 and t[0] in _ES_TENS and t[1] == 'y' and t[2] in _ES_UNITS and 1 <= _ES_UNITS[t[2]] <= 9:
        return _ES_TENS[t[0]] + _ES_UNITS[t[2]]
    raise ValueError('Amount is ambiguous. Say a full number, such as cinco mil.')


def _es_under_1000(t):
    if not t: raise ValueError('Incomplete amount.')
    if t == ['cien']: return 100
    if t[0] in _ES_HUND:
        if t[0] == 'ciento' and len(t) == 1: raise ValueError('Incomplete amount.')
        return _ES_HUND[t[0]] + (_es_under_100(t[1:]) if len(t) > 1 else 0)
    return _es_under_100(t)


def es_number(words):
    t = [_fold(w) for w in words.split()]
    if t.count('mil') > 1: raise ValueError('Ambiguous amount.')
    if 'mil' in t:
        i = t.index('mil')
        left = 1 if i == 0 else _es_under_1000(t[:i])
        if i and t[:i] in (['un'], ['una']): raise ValueError('Ambiguous amount.')
        return left * 1000 + (_es_under_1000(t[i + 1:]) if t[i + 1:] else 0)
    return _es_under_1000(t)


# ---------------------------------------------------------------- German
_DE_UNITS = {'ein': 1, 'eins': 1, 'zwei': 2, 'drei': 3, 'vier': 4, 'fuenf': 5, 'sechs': 6, 'sieben': 7, 'acht': 8, 'neun': 9}
_DE_TEENS = {'zehn': 10, 'elf': 11, 'zwoelf': 12, 'dreizehn': 13, 'vierzehn': 14, 'fuenfzehn': 15, 'sechzehn': 16,
             'siebzehn': 17, 'achtzehn': 18, 'neunzehn': 19}
_DE_TENS = {'zwanzig': 20, 'dreissig': 30, 'vierzig': 40, 'fuenfzig': 50, 'sechzig': 60, 'siebzig': 70, 'achtzig': 80,
            'neunzig': 90}


def _de_norm(text):
    text = text.casefold().replace('ß', 'ss').replace('ä', 'ae').replace('ö', 'oe').replace('ü', 'ue')
    return re.sub(r'[\s\-]+', '', text)


def _de_under_100(s):
    if s in _DE_UNITS or s in _DE_TEENS or s in _DE_TENS:
        return {**_DE_UNITS, **_DE_TEENS, **_DE_TENS}[s]
    m = re.fullmatch(r'(ein|zwei|drei|vier|fuenf|sechs|sieben|acht|neun)und(zwanzig|dreissig|vierzig|fuenfzig|sechzig|siebzig|achtzig|neunzig)', s)
    if m: return _DE_UNITS[m[1]] + _DE_TENS[m[2]]
    raise ValueError('Amount is ambiguous. Say a full number, such as fünftausend.')


def _de_under_1000(s):
    if not s: raise ValueError('Incomplete amount.')
    if s.count('hundert') > 1: raise ValueError('Ambiguous amount.')
    if 'hundert' in s:
        left, right = s.split('hundert')
        coef = 1 if left == '' else _DE_UNITS.get(left)
        if coef is None or not 1 <= coef <= 9 or left == 'eins': raise ValueError('Unrecognized hundred amount.')
        return coef * 100 + (_de_under_100(right) if right else 0)
    return _de_under_100(s)


def de_number(words):
    s = _de_norm(words)
    if s.count('tausend') > 1: raise ValueError('Ambiguous amount.')
    if 'tausend' in s:
        left, right = s.split('tausend')
        if left == 'eins': raise ValueError('Ambiguous amount.')
        return (1 if left == '' else _de_under_1000(left)) * 1000 + (_de_under_1000(right) if right else 0)
    return _de_under_1000(s)


# ---------------------------------------------------------------- Korean (Sino-Korean numerals, used for money)
_KO_D = dict(zip('일이삼사오육칠팔구', range(1, 10)))


def _ko_under_10000(s):
    m = re.fullmatch(r'(?:([일이삼사오육칠팔구])?천)?(?:([일이삼사오육칠팔구])?백)?(?:([일이삼사오육칠팔구])?십)?([일이삼사오육칠팔구])?', s)
    if not s or not m: raise ValueError('Amount is ambiguous. Say a full number, such as 오천.')
    total = 0
    # coefficients: a unit character present with no digit before it means 1
    for unit_char, unit, coef in (('천', 1000, m[1]), ('백', 100, m[2]), ('십', 10, m[3])):
        if unit_char in s:
            total += (_KO_D[coef] if coef else 1) * unit
    if m[4]: total += _KO_D[m[4]]
    return total


def ko_number(text):
    s = re.sub(r'\s+', '', text)
    if re.search(r'\d', s) and re.search(r'[천백십만]', s):          # Whisper often writes '5천' or '1만5천'
        s = re.sub(r'\d', lambda d: '영일이삼사오육칠팔구'[int(d[0])], s)
        if '영' in s: raise ValueError('Amount is ambiguous.')
    if s.count('만') > 1: raise ValueError('Ambiguous amount.')
    if '만' in s:
        left, right = s.split('만')
        return (1 if left == '' else _ko_under_10000(left)) * 10000 + (_ko_under_10000(right) if right else 0)
    return _ko_under_10000(s)


# ---------------------------------------------------------------- shared helpers
def eu_amount(s):
    """European digit grouping. Refuses forms that could mean two different amounts."""
    if re.fullmatch(r'\d+', s): return s
    if re.fullmatch(r'\d{1,3}(?:\.\d{3})+', s): return s.replace('.', '')
    if re.fullmatch(r'\d+,\d{1,2}', s): return s.replace(',', '.')
    if re.fullmatch(r'\d{1,3}(?:\.\d{3})+,\d{1,2}', s): return s.replace('.', '').replace(',', '.')
    if re.fullmatch(r'\d+\.\d{1,2}', s): return s
    raise ValueError('Amount is ambiguous. Write 5000, or 5.000 or 5,50 in the usual way for your language.')


def _longest_number_suffix(tokens, parse, limit=6):
    """Name-first commands put the amount after the name. Take the longest suffix that is a valid number."""
    for k in range(min(limit, len(tokens) - 1), 0, -1):
        try:
            return ' '.join(tokens[:-k]), parse(' '.join(tokens[-k:]))
        except ValueError:
            continue
    raise ValueError('Amount is ambiguous. Say a full number, such as five thousand.')


_ES_V = r'(?:pagar|paga|págale|pagale|enviar|envía|envia|envíale|enviale|mandar|manda|mándale|mandale|transferir|transfiere)'
_DE_INF = r'(?:überweisen|ueberweisen|senden|schicken|zahlen|bezahlen)'
_DE_V = r'(?:bezahle|zahle|zahl|überweise|ueberweise|überweis|ueberweis|sende|schicke|schick)'
_KO_V = r'(?:송금|이체|보내|지불)\s*(?:해\s*줘요|해\s*주세요|해\s*줘|해\s*요|하세요|해|줘요|줘|주세요|세요|라)?'
_DIG = r'\d[\d.,]*'
_KO_W = r'[영공일이삼사오육칠팔구십백천만]+'
_KO_AMT = rf'(\d[\d,]*(?:\.\d{{1,2}})?[천백십만\d]*|{_KO_W}(?:\s+{_KO_W})*)'

_FORBIDDEN = {
    'es': r'(?:\b(?:y|o|luego|entonces|a|rupias?|rupees|rs|menos|más|mas|negativo|paga|pagar|envía|envia|enviar|manda|mandar|transfiere|transferir)\b)',
    'de': r'(?:\b(?:und|oder|dann|an|rupien|rupie|rupees|rs|minus|plus|negativ|zahle|bezahle|sende|schicke|überweise|ueberweise)\b)',
    'ko': r'(?:그리고|또는|그다음|그 다음|루피|마이너스|송금|이체|보내|지불)',
}


def _strip_politeness(text, lang):
    if lang == 'es':
        text = re.sub(r'^(?:por favor,?\s+|(?:puedes|podrías|podrias|podría|podria)\s+(?:por favor\s+)?)', '', text, flags=re.I)
        text = re.sub(r',?\s+por favor$', '', text, flags=re.I)
    elif lang == 'de':
        text = re.sub(r'^(?:bitte\s+|(?:kannst|könntest|koenntest) du\s+(?:bitte\s+)?)', '', text, flags=re.I)
        text = re.sub(r',?\s+bitte$', '', text, flags=re.I)
    return text


def _words_or_digits(raw, parse_words, lang):
    raw = raw.strip()
    if re.fullmatch(_DIG, raw):
        return eu_amount(raw)
    return str(parse_words(raw))


def parse_other(text):
    """Return (name, canonical amount) for a Spanish, German or Korean command, or None if the text is none of them."""
    out = _spanish(text) or _german(text) or _korean(text)
    return out


def _clean(name, lang):
    if re.search(_FORBIDDEN[lang], name, re.I):
        raise ValueError('Use one payment command at a time.')
    return name.strip().rstrip(',')


def _spanish(text):
    text = _strip_politeness(text, 'es')
    cur = CUR_ES
    m = re.fullmatch(rf'{_ES_V}\s+(?:rupees\s+)?({_DIG})(?:\s*{cur})?\s+a\s+(.+)', text, re.I)
    if m: return _clean(m[2], 'es'), eu_amount(m[1])
    m = re.fullmatch(rf'{_ES_V}\s+(.+?)\s+{cur}\s+a\s+(.+)', text, re.I)
    if m and not re.search(r'\d', m[1]): return _clean(m[2], 'es'), str(es_number(m[1]))
    m = re.fullmatch(rf'{_ES_V}\s+a\s+(.+?)\s+(?:rupees\s+)?({_DIG})(?:\s*{cur})?', text, re.I)
    if m: return _clean(m[1], 'es'), eu_amount(m[2])
    m = re.fullmatch(rf'{_ES_V}\s+a\s+(.+)\s+{cur}', text, re.I)
    if m:
        name, value = _longest_number_suffix(m[1].split(), es_number)
        return _clean(name, 'es'), str(value)
    return None


def _german(text):
    text = _strip_politeness(text, 'de')
    cur = CUR_DE
    m = re.fullmatch(rf'(?:rupees\s+)?({_DIG})(?:\s*{cur})?\s+an\s+(.+?)\s+{_DE_INF}', text, re.I)   # verb last: '300 Rupien an Sneha überweisen'
    if m: return _clean(m[2], 'de'), eu_amount(m[1])
    m = re.fullmatch(rf'(.+?)\s+{cur}\s+an\s+(.+?)\s+{_DE_INF}', text, re.I)
    if m and not re.search(r'\d', m[1]): return _clean(m[2], 'de'), str(de_number(m[1]))
    m = re.fullmatch(rf'{_DE_V}\s+(?:rupees\s+)?({_DIG})(?:\s*{cur})?\s+an\s+(.+)', text, re.I)
    if m: return _clean(m[2], 'de'), eu_amount(m[1])
    m = re.fullmatch(rf'{_DE_V}\s+(.+?)\s+{cur}\s+an\s+(.+)', text, re.I)
    if m and not re.search(r'\d', m[1]): return _clean(m[2], 'de'), str(de_number(m[1]))
    m = re.fullmatch(rf'{_DE_V}\s+(?:an\s+)?(.+?)\s+(?:rupees\s+)?({_DIG})(?:\s*{cur})?', text, re.I)
    if m: return _clean(m[1], 'de'), eu_amount(m[2])
    m = re.fullmatch(rf'{_DE_V}\s+(?:an\s+)?(.+)\s+{cur}', text, re.I)
    if m:
        name, value = _longest_number_suffix(m[1].split(), de_number)
        return _clean(name, 'de'), str(value)
    return None


def _korean(text):
    text = re.sub(r'\s*(?:[.!?。])$', '', text)
    pre = r'(?:에게|한테|께)'
    m = re.fullmatch(rf'(.+?)\s*{pre}\s*{_KO_AMT}\s*{CUR_KO}\s*(?:를|을)?\s*{_KO_V}', text)
    if m: name, amount = m[1], m[2]
    else:
        m = re.fullmatch(rf'{_KO_AMT}\s*{CUR_KO}\s*(?:를|을)?\s*(.+?)\s*{pre}\s*{_KO_V}', text)
        if not m: return None
        amount, name = m[1], m[2]
    value = amount.replace(',', '') if re.fullmatch(r'\d[\d,]*(?:\.\d{1,2})?', amount) else str(ko_number(amount))
    return _clean(name, 'ko'), value
