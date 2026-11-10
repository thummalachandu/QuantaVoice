"""User-managed demo directory. No bank lookup or real payment routing."""
from dataclasses import dataclass, asdict
from pathlib import Path
import json, secrets, unicodedata, re

def norm(value): return unicodedata.normalize('NFC',value).strip().casefold()

def valid_name(value):
    value=' '.join(unicodedata.normalize('NFC',value).split())
    if not 1<=len(value)<=60 or not any(c.isalpha() for c in value):
        raise ValueError('Name must contain letters and be at most 60 characters.')
    if any(not (unicodedata.category(c)[0] in 'LM' or c in " .'-") for c in value):
        raise ValueError('Use letters, spaces, apostrophes, dots or hyphens in names.')
    return value

@dataclass(frozen=True)
class Contact:
    id: str
    name: str
    phone: str
    payment_id: str
    aliases: tuple=()
    @property
    def label(self): return f'{self.name} | {self.phone} | {self.payment_id} [demo]'

CONTACTS=[Contact('demo-priya-1','Priya','******1201','priya.family@demo'),
          Contact('demo-priya-2','Priya','******8402','priya.work@demo')]
CONTACTS.extend(Contact('demo-'+n.lower(),n,'******'+s,n.lower()+'@demo') for n,s in
                [('Rahul','2303'),('Sneha','3404'),('Amit','4505'),('Vikram','5606'),('Ananya','6707')])
DIRECTORY=Path(__file__).resolve().parent/'recipients.json'

def matches(name):
    return [c for c in CONTACTS if norm(name) in {norm(c.name),*(norm(a) for a in c.aliases)}]

def resolve(contact_id):
    for c in CONTACTS:
        if c.id==contact_id: return c
    raise ValueError('Choose a saved recipient account; names alone are insufficient.')

def add_contact(name, phone, payment_id, aliases=(), persist=True):
    name=valid_name(name); aliases=tuple(valid_name(a) for a in aliases if a.strip())
    digits=''.join(str(unicodedata.decimal(c)) for c in phone if c.isdecimal())
    if not 4<=len(digits)<=15: raise ValueError('Enter a number with 4–15 digits. Only its last four are stored.')
    payment_id=payment_id.strip()
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,64}',payment_id):
        raise ValueError('Enter a payment ID in name@provider format. This demo cannot validate bank ownership.')
    if any(c.payment_id.casefold()==payment_id.casefold() for c in CONTACTS): raise ValueError('That payment ID is already saved.')
    contact=Contact('local-'+secrets.token_hex(8),name,'******'+digits[-4:],payment_id,aliases)
    if persist:
        DIRECTORY.parent.mkdir(parents=True,exist_ok=True)
        records=[asdict(c) for c in CONTACTS if c.id.startswith('local-')]+[asdict(contact)]
        temporary=DIRECTORY.with_suffix('.tmp'); temporary.write_text(json.dumps(records,ensure_ascii=False),encoding='utf-8'); temporary.replace(DIRECTORY)
    CONTACTS.append(contact); return contact

def load_contacts():
    if not DIRECTORY.exists(): return
    data=json.loads(DIRECTORY.read_text(encoding='utf-8'))
    if not isinstance(data,list): raise ValueError('Invalid recipient directory.')
    for item in data:
        c=Contact(**item); valid_name(c.name)
        if not c.id.startswith('local-'): raise ValueError('Invalid local contact ID.')
        if not any(x.id==c.id for x in CONTACTS): CONTACTS.append(c)
