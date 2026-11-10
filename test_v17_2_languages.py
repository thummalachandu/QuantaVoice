"""v17.2 B10: Spanish, German and Korean payment commands, strict like the existing languages."""
import unittest

import command_langs as cl
from challenge_phrase import ChallengeService
from voice_command import parse_payment


class Numbers(unittest.TestCase):
    def test_spanish(self):
        for text, n in [('cinco mil', 5000), ('mil', 1000), ('mil quinientos', 1500), ('dos mil doscientos cincuenta', 2250),
                        ('treinta y cinco', 35), ('veintiún', 21), ('veintidós', 22), ('cien', 100), ('ciento cinco', 105),
                        ('quince', 15), ('dieciséis', 16), ('cuarenta mil', 40000), ('novecientos noventa y nueve', 999)]:
            self.assertEqual(cl.es_number(text), n, text)
        for bad in ['', 'cinco cinco', 'un mil', 'mil mil', 'ciento', 'treinta cinco', 'cuarenta y cero', 'veinte y uno', 'dos cien', 'banana']:
            with self.subTest(bad=bad), self.assertRaises(ValueError): cl.es_number(bad)

    def test_german(self):
        for text, n in [('fünftausend', 5000), ('eintausend', 1000), ('tausend', 1000), ('zweitausendzweihundertfünfzig', 2250),
                        ('zwei tausend fünf hundert', 2500), ('einundzwanzig', 21), ('hundert', 100), ('dreißig', 30), ('dreissig', 30),
                        ('zwölf', 12), ('neunundneunzig', 99), ('vierzigtausend', 40000), ('einhundertfünf', 105)]:
            self.assertEqual(cl.de_number(text), n, text)
        for bad in ['', 'fünffünf', 'tausendtausend', 'zwanzigeins', 'hundertundfünf', 'einsundzwanzig', 'bananen', 'neunzehnzig']:
            with self.subTest(bad=bad), self.assertRaises(ValueError): cl.de_number(bad)

    def test_korean(self):
        for text, n in [('오천', 5000), ('이만 오천', 25000), ('이백오십', 250), ('천', 1000), ('만', 10000), ('만 오천', 15000),
                        ('5천', 5000), ('1만5천', 15000), ('삼십', 30), ('구천구백구십구', 9999), ('십', 10)]:
            self.assertEqual(cl.ko_number(text), n, text)
        for bad in ['', '오오', '천천', '만만', '오십오십', '영', '10만', '백이십삼천']:
            with self.subTest(bad=bad), self.assertRaises(ValueError): cl.ko_number(bad)

    def test_european_digit_grouping(self):
        self.assertEqual(cl.eu_amount('5.000'), '5000'); self.assertEqual(cl.eu_amount('5,50'), '5.50')
        self.assertEqual(cl.eu_amount('1.234,5'), '1234.5'); self.assertEqual(cl.eu_amount('5000.50'), '5000.50')
        for bad in ['5,000', '1,234,567', '5.5.5', '5,500,5', '1.23.456']:
            with self.subTest(bad=bad), self.assertRaises(ValueError): cl.eu_amount(bad)


class Commands(unittest.TestCase):
    def ok(self, phrase, name, amount):
        self.assertEqual(parse_payment(phrase), (name, amount), phrase)

    def bad(self, phrase):
        with self.assertRaises(ValueError, msg=phrase): parse_payment(phrase)

    def test_spanish_good(self):
        for p, n, a in [('Paga 5000 rupias a Chandu', 'Chandu', '5000.00'), ('paga 5000 a Chandu', 'Chandu', '5000.00'),
                        ('Transfiere cinco mil rupias a Chandu', 'Chandu', '5000.00'), ('Envía a Rahul treinta y cinco rupias', 'Rahul', '35.00'),
                        ('Manda a Chandu 250 rupias', 'Chandu', '250.00'), ('Por favor paga 5.000 rupias a Priya', 'Priya', '5000.00'),
                        ('Paga ₹5000 a Sneha', 'Sneha', '5000.00'), ('Envía a José María mil quinientos rupias', 'José María', '1500.00'),
                        ('Paga 5,50 rupias a Amit, por favor', 'Amit', '5.50'), ('Paga dos mil rupias a Ana', 'Ana', '2000.00')]:
            with self.subTest(p=p): self.ok(p, n, a)

    def test_german_good(self):
        for p, n, a in [('Zahle 5000 Rupien an Chandu', 'Chandu', '5000.00'), ('Überweise Chandu 5000 Rupien', 'Chandu', '5000.00'),
                        ('Überweise Chandu fünftausend Rupien', 'Chandu', '5000.00'), ('Sende an Priya zweitausendzweihundert Rupien', 'Priya', '2200.00'),
                        ('Bitte zahle 5.000 Rupien an Chandu', 'Chandu', '5000.00'), ('Zahle 5,50 Rupien an Chandu', 'Chandu', '5.50'),
                        ('Kannst du bitte 300 Rupien an Sneha überweisen?', 'Sneha', '300.00'), ('Zahle zweihundert Rupien an Jürgen', 'Jürgen', '200.00'),
                        ('Schick Amit hundertfünfzig Rupien, bitte', 'Amit', '150.00')]:
            with self.subTest(p=p): self.ok(p, n, a)

    def test_korean_good(self):
        for p, n, a in [('찬두에게 5000 루피 송금해줘', '찬두', '5000.00'), ('찬두에게 오천 루피를 보내줘', '찬두', '5000.00'),
                        ('이만 오천 루피를 찬두에게 송금해주세요', '찬두', '25000.00'), ('찬두에게 5천 루피 이체해 줘', '찬두', '5000.00'),
                        ('찬두한테 5,000루피 보내', '찬두', '5000.00'), ('5000 루피를 민수에게 송금해요', '민수', '5000.00'),
                        ('영희에게 이천오백 루피 송금해줘.', '영희', '2500.00')]:
            with self.subTest(p=p): self.ok(p, n, a)

    def test_one_payment_only(self):
        for p in ['Paga 5000 rupias a Chandu y Rahul', 'Paga 5000 rupias a Chandu y paga 100 rupias a Rahul',
                  'Zahle 5000 Rupien an Chandu und Rahul', 'Zahle 5000 Rupien an Chandu dann sende 100 Rupien an Amit',
                  '찬두에게 오천 루피 송금해줘 그리고 철수에게 100 루피 송금해줘', 'Paga 5000 rupias a Chandu o a Rahul']:
            with self.subTest(p=p): self.bad(p)

    def test_ambiguous_or_unsafe_amounts_are_refused(self):
        for p in ['Zahle 5,000 Rupien an Chandu', 'Paga 5,000 rupias a Chandu', 'Paga 1,234,567 rupias a Chandu', 'Paga cien mil rupias a Chandu',
                  'Zahle 0 Rupien an Chandu', 'Zahle hunderttausend Rupien an Chandu', '찬두에게 십만 루피 송금해줘', '찬두에게 0 루피 송금해줘',
                  'Paga menos 5000 rupias a Chandu', 'Paga cinco cinco rupias a Chandu', 'Zahle fünffünf Rupien an Chandu',
                  'Paga 5000 rupias', 'Zahle fünftausend an', '찬두에게 루피 송금해줘', 'Paga a Chandu rupias']:
            with self.subTest(p=p): self.bad(p)

    def test_existing_languages_are_unchanged(self):
        self.ok('Pay Chandu 5000', 'Chandu', '5000.00'); self.ok('चंदू को 5000 रुपये भेजो', 'चंदू', '5000.00')
        self.ok('చందు కి 5000 రూపాయలు పంపు', 'చందు', '5000.00'); self.ok('send 5000 rupees to Priya', 'Priya', '5000.00')
        self.bad('Pay Chandu 5000 and Rahul 100')

    def test_error_message_lists_the_new_languages(self):
        with self.assertRaises(ValueError) as cm: parse_payment('hello')
        for sample in ('Paga 5000 rupias a Chandu', 'Zahle 5000 Rupien an Chandu', '찬두에게'): self.assertIn(sample, str(cm.exception))


class Challenge(unittest.TestCase):
    def test_korean_challenge_digits(self):
        svc = ChallengeService(length=6); ch = svc.issue('d' * 64, 'ko')
        self.assertTrue(all(w in '영일이삼사오육칠팔구 ' for w in ch['spoken_form']))
        self.assertTrue(svc.verify(ch['challenge_id'], 'd' * 64, ch['spoken_form']))
        ch = svc.issue('d' * 64, 'ko'); joined = ch['spoken_form'].replace(' ', '')   # Whisper may join syllables
        self.assertTrue(svc.verify(ch['challenge_id'], 'd' * 64, joined))
        ch = svc.issue('d' * 64, 'ko'); self.assertFalse(svc.verify(ch['challenge_id'], 'd' * 64, ch['spoken_form'] + ' 영 사과'))

    def test_korean_zero_alias(self):
        self.assertEqual(ChallengeService.transcript_to_digits('공 일 이 삼', 'ko'), '0123')
        self.assertEqual(ChallengeService.transcript_to_digits('공일이삼', 'ko'), '0123')
        self.assertIsNone(ChallengeService.transcript_to_digits('공일 hello', 'ko'))

    def test_spanish_german_challenge_still_work(self):
        svc = ChallengeService(); 
        for lang in ('es', 'de'):
            ch = svc.issue('e' * 64, lang); self.assertTrue(svc.verify(ch['challenge_id'], 'e' * 64, ch['spoken_form']))


class WhisperGate(unittest.TestCase):
    def test_new_languages_are_accepted_and_unknown_still_refused(self):
        import whisper_engine
        for lang in ('es', 'de', 'ko'):
            with self.assertRaises(RuntimeError): whisper_engine.make_recognizer(object(), lang, 16000)   # model not installed here
        with self.assertRaises(ValueError): whisper_engine.make_recognizer(object(), 'fr', 16000)


from test_v17_gui import GuiBase

class GuiModels(GuiBase):
    def test_every_model_choice_has_a_model_path(self):
        app = self.ResearchVoice(self.root)
        values = list(app.model_choice['values'])
        self.assertEqual(len(values), len(app.model_paths))
        for lang in ('Spanish', 'German', 'Korean'):
            i = next(i for i, v in enumerate(values) if lang in v)
            self.assertEqual(app.model_paths[i].name, 'whisper-' + {'Spanish': 'es', 'German': 'de', 'Korean': 'ko'}[lang])


if __name__ == '__main__':
    unittest.main()
