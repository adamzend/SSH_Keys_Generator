# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""Local named connections; never persist credentials."""
import json
import os
from pathlib import Path

FIELDS = ('host', 'port', 'user', 'key_path', 'mode')

def read_export(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(2_000_001)
    if len(raw) > 2_000_000:raise ValueError('Plik profili jest zbyt duży (maks. 2 MB).')
    data = json.loads(raw.decode('utf-8-sig'))
    return validate_export(data)

def validate_export(data):
    if not isinstance(data, dict) or data.get('format') != 'SSH_Keys_Generator profiles' or data.get('version') != 1:
        raise ValueError('Nieobsługiwany format eksportu profili.')
    items = data.get('profiles')
    if not isinstance(items, dict) or len(items) > 1000:
        raise ValueError('Nieprawidłowa lista profili (maks. 1000).')
    result = {}
    for name, value in items.items():
        if not name.strip() or len(name) > 100 or name != name.strip():raise ValueError('Nieprawidłowa nazwa profilu.')
        if not isinstance(value, dict) or any(not isinstance(value.get(k), str) for k in FIELDS):
            raise ValueError('Nieprawidłowe pola profilu: '+name)
        profile = clean(value)
        if any(len(v) > 4096 or any(ord(c) < 32 for c in v) for v in profile.values()):
            raise ValueError('Nieprawidłowe wartości profilu: '+name)
        if (not profile['host'] or not profile['user'] or
            any(c.isspace() for c in profile['host']+profile['user']) or ',' in profile['user'] or
            not profile['port'].isascii() or not profile['port'].isdigit() or
            not 1 <= int(profile['port']) <= 65535 or profile['mode'] not in ('Hasło', 'Klucz')):
            raise ValueError('Nieprawidłowy adres, login, port lub metoda logowania: '+name)
        result[name] = profile
    return result

def clean(data):
    if not isinstance(data, dict):
        raise ValueError('Nieprawidłowy profil.')
    return {k: str(data.get(k, 'Hasło' if k == 'mode' else '22' if k == 'port' else '')) for k in FIELDS}

class Profiles:
    def __init__(self, directory):
        self.path = Path(directory) / 'profiles.json'
        self.items = {}
        self.selected = ''
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(data, dict) or not isinstance(data.get('profiles'), dict):
                raise ValueError('Nieprawidłowy plik profili.')
            self.items = {name: clean(value) for name, value in data['profiles'].items()}
            self.selected = data.get('selected', '')
            if self.selected not in self.items:self.selected = ''
        else:
            legacy = self.path.with_name('last_connection.json')
            if legacy.exists():
                old = json.loads(legacy.read_text(encoding='utf-8'))
                profile = clean(old)
                profile['mode'] = 'Klucz' if profile['key_path'] else 'Hasło'
                self.items['Poprzednie połączenie'] = profile
                self.selected = 'Poprzednie połączenie'
                self.write(self.items, self.selected)

    def write(self, items, selected):
        safe = {name: clean(value) for name, value in items.items()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps({'profiles': safe, 'selected': selected}, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(temp, self.path)
        self.items, self.selected = safe, selected

    def save(self, name, profile):
        name = name.strip()
        if not name or len(name) > 100:raise ValueError('Nazwa musi mieć od 1 do 100 znaków.')
        self.write({**self.items, name: clean(profile)}, name)

    def delete(self, name):
        items = dict(self.items)
        del items[name]
        self.write(items, '' if self.selected == name else self.selected)

    def export_file(self, path):
        if Path(path).resolve() == self.path.resolve():
            raise ValueError('Wybierz inny plik niż wewnętrzny profiles.json programu.')
        data = {'format': 'SSH_Keys_Generator profiles', 'version': 1,
                'profiles': {name: clean(value) for name, value in self.items.items()}}
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

    def merge(self, incoming, overwrite=False):
        additions = {name: clean(value) for name, value in incoming.items()
                     if overwrite or name not in self.items}
        if additions:self.write({**self.items, **additions}, self.selected)
        return len(additions), len(incoming)-len(additions)
