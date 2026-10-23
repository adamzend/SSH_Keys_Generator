# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""Versioned, authenticated encrypted migration bundles. Never stage plaintext archives."""
import base64
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from profiles import clean, validate_export
from keys import restrict_folder

MAGIC = b'SSHKG-BUNDLE\x01'
MAX_BUNDLE = 32 * 1024 * 1024
MAX_KEY = 1024 * 1024


def derive(password, salt):
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise ValueError('Nieprawidłowa długość hasła pakietu.')
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode('utf-8'))


def key_suffix(raw):
    if not raw or len(raw) > MAX_KEY:raise ValueError('Nieprawidłowy rozmiar klucza.')
    if raw.startswith((b'PuTTY-User-Key-File-2:', b'PuTTY-User-Key-File-3:')):return '.ppk'
    if raw.startswith((b'-----BEGIN OPENSSH PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                       b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN DSA PRIVATE KEY-----',
                       b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN ENCRYPTED PRIVATE KEY-----')):return '.key'
    raise ValueError('Plik nie ma rozpoznawanego nagłówka prywatnego klucza SSH (PPK/PEM/OpenSSH).')


def export_bundle(store, destination, password):
    if len(password) < 12:raise ValueError('Hasło pakietu musi mieć co najmniej 12 znaków.')
    items = {n: clean(p) for n,p in store.items.items()}
    validate_export({'format':'SSH_Keys_Generator profiles','version':1,'profiles':items})
    if not items:raise ValueError('Brak zapisanych profili.')
    target = Path(destination).resolve()
    protected = [store.path.resolve()]
    protected += [Path(p['key_path']).resolve() for p in items.values() if p['key_path']]
    if target in protected:raise ValueError('Nie można nadpisać klucza źródłowego ani pliku profili.')
    keys, refs = {}, {}
    for name, profile in items.items():
        path = profile['key_path']
        if not path:
            if profile['mode']=='Klucz':raise ValueError('Brak ścieżki klucza w profilu: '+name)
            continue
        with Path(path).open('rb') as stream:raw = stream.read(MAX_KEY+1)
        key_suffix(raw)
        identity = hashlib.sha256(raw).hexdigest()
        keys[identity] = base64.b64encode(raw).decode('ascii')
        refs[name] = identity
        if sum(len(value) for value in keys.values()) > MAX_BUNDLE-2_000_000:
            raise ValueError('Pakiet przekracza limit 32 MiB.')
    data = json.dumps({'profiles':items,'keys':keys,'refs':refs}, ensure_ascii=False).encode('utf-8')
    if len(data) > MAX_BUNDLE-100:raise ValueError('Pakiet przekracza limit 32 MiB.')
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC+salt+nonce
    encrypted = header+AESGCM(derive(password,salt)).encrypt(nonce,data,header)
    # Only ciphertext is written to a temporary file, on the destination volume.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.sshkg-', delete=False) as stream:
            temporary=Path(stream.name);stream.write(encrypted);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,target)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()
    return len(items), len(keys)


def read_bundle(path, password):
    with Path(path).open('rb') as stream:blob=stream.read(MAX_BUNDLE+1)
    length=len(MAGIC)+28
    if len(blob)>MAX_BUNDLE or len(blob)<length+16 or not blob.startswith(MAGIC):
        raise ValueError('Nieobsługiwany lub uszkodzony pakiet (maks. 32 MiB).')
    header=blob[:length];salt=header[len(MAGIC):len(MAGIC)+16];nonce=header[-12:]
    try:raw=AESGCM(derive(password,salt)).decrypt(nonce,blob[length:],header)
    except InvalidTag:raise ValueError('Nieprawidłowe hasło lub uszkodzony pakiet. Niczego nie zaimportowano.') from None
    try:data=json.loads(raw.decode('utf-8'))
    except (ValueError,RecursionError):raise ValueError('Nieprawidłowa zawartość pakietu.') from None
    if not isinstance(data,dict):raise ValueError('Nieprawidłowy pakiet.')
    items=validate_export({'format':'SSH_Keys_Generator profiles','version':1,'profiles':data.get('profiles')})
    encoded,refs=data.get('keys'),data.get('refs')
    if not isinstance(encoded,dict) or not isinstance(refs,dict) or len(encoded)>1000:
        raise ValueError('Nieprawidłowa lista kluczy.')
    keys={}
    for identity,value in encoded.items():
        if not isinstance(value,str):raise ValueError('Nieprawidłowy klucz.')
        raw=base64.b64decode(value,validate=True)
        key_suffix(raw)
        if hashlib.sha256(raw).hexdigest()!=identity:raise ValueError('Nieprawidłowy identyfikator klucza.')
        keys[identity]=raw
    if set(refs)-set(items):raise ValueError('Nieprawidłowe odwołanie profilu.')
    for name,profile in items.items():
        identity=refs.get(name)
        if identity is not None and (not isinstance(identity,str) or identity not in keys):
            raise ValueError('Brak klucza dla profilu: '+name)
        if (profile['key_path'] or profile['mode']=='Klucz') and identity is None:
            raise ValueError('Pakiet nie zawiera wymaganego klucza: '+name)
    return items,keys,refs


def import_bundle(store, bundle, overwrite=False):
    items,keys,refs=bundle
    chosen={n:dict(p) for n,p in items.items() if overwrite or n not in store.items}
    if not chosen:return 0,len(items)
    # Never use archive-supplied paths or filenames; never overwrite existing keys.
    root=store.path.parent/'imported_keys'
    root.mkdir(parents=True,exist_ok=True)
    folder=root/uuid.uuid4().hex
    folder.mkdir(mode=0o700)
    created=[]
    try:
        restrict_folder(folder)
        paths={}
        for name,profile in chosen.items():
            identity=refs.get(name)
            if identity is None:
                profile['key_path']='';continue
            if identity not in paths:
                raw=keys[identity];target=folder/(identity+key_suffix(raw))
                with target.open('xb') as stream:
                    created.append(target);stream.write(raw)
                if os.name!='nt':target.chmod(0o600)
                paths[identity]=str(target.resolve())
            profile['key_path']=paths[identity]
        store.merge(chosen,overwrite)
    except Exception:
        for path in created:path.unlink()
        folder.rmdir()
        raise
    if not created:folder.rmdir()
    return len(chosen),len(items)-len(chosen)
