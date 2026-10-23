# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""Local RSA key generation and PuTTY PPK v2/v3 interoperability."""
import base64
import hashlib
import hmac
import io
import os
import struct
import textwrap
from pathlib import Path

import paramiko
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def string(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return struct.pack('>I', len(value)) + value


def mpint(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if raw and raw[0] & 128:
        raw = b'\0' + raw
    return string(raw)


def fingerprint(blob):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def ppk_encode(key, password, comment):
    if '\n' in comment or '\r' in comment:
        raise ValueError('Komentarz klucza musi zajmować jeden wiersz.')
    n = key.private_numbers()
    public = string('ssh-rsa') + mpint(n.public_numbers.e) + mpint(n.public_numbers.n)
    private = mpint(n.d) + mpint(n.p) + mpint(n.q) + mpint(n.iqmp)
    encryption = 'aes256-cbc' if password else 'none'
    headers = []
    mac_key = b''
    if password:
        salt = os.urandom(16)
        material = hash_secret_raw(password.encode(), salt, 3, 65536, 1, 80, Type.ID)
        private += os.urandom((-len(private)) % 16)
        mac_key = material[48:]
        enc = Cipher(algorithms.AES(material[:32]), modes.CBC(material[32:48])).encryptor()
        encrypted = enc.update(private) + enc.finalize()
        headers = ['Key-Derivation: Argon2id', 'Argon2-Memory: 65536', 'Argon2-Passes: 3',
                   'Argon2-Parallelism: 1', 'Argon2-Salt: ' + salt.hex()]
    else:
        encrypted = private
    mac = hmac.new(mac_key, b''.join(string(x) for x in ('ssh-rsa', encryption, comment, public, private)), hashlib.sha256).hexdigest()
    pub_lines = textwrap.wrap(base64.b64encode(public).decode(), 64)
    priv_lines = textwrap.wrap(base64.b64encode(encrypted).decode(), 64)
    return '\n'.join(['PuTTY-User-Key-File-3: ssh-rsa', 'Encryption: ' + encryption,
                      'Comment: ' + comment, 'Public-Lines: ' + str(len(pub_lines)), *pub_lines,
                      *headers, 'Private-Lines: ' + str(len(priv_lines)), *priv_lines, 'Private-MAC: ' + mac, ''])


def ppk_decode(text, password):
    lines = iter(text.splitlines())
    fields = {}
    for line in lines:
        k, v = line.split(': ', 1)
        if k in ('Public-Lines', 'Private-Lines'):
            count = int(v)
            if not 0 < count < 10000:
                raise ValueError('Nieprawidłowa długość PPK.')
            fields[k] = base64.b64decode(''.join(next(lines) for _ in range(count)), validate=True)
        else:
            fields[k] = v
    version = 3 if 'PuTTY-User-Key-File-3' in fields else 2
    if fields.get('PuTTY-User-Key-File-' + str(version)) != 'ssh-rsa':
        raise ValueError('Import PPK obsługuje RSA. Dla innych typów wybierz format OpenSSH.')
    private = fields['Private-Lines']
    encryption = fields['Encryption']
    secret = password.encode() if encryption != 'none' else b''
    if version == 3:
        material = b''
        if encryption != 'none':
            memory, passes, parallel = (int(fields['Argon2-' + x]) for x in ('Memory', 'Passes', 'Parallelism'))
            if not (8 <= memory <= 262144 and 1 <= passes <= 100 and 1 <= parallel <= 16):
                raise ValueError('Parametry PPK przekraczają bezpieczne limity odczytu.')
            flavor = {'Argon2id': Type.ID, 'Argon2i': Type.I, 'Argon2d': Type.D}[fields['Key-Derivation']]
            material = hash_secret_raw(secret, bytes.fromhex(fields['Argon2-Salt']), passes, memory, parallel, 80, flavor)
        cipher_key, iv, mac_key = material[:32], material[32:48], material[48:]
        digest = hashlib.sha256
    else:
        cipher_key = b''.join(hashlib.sha1(struct.pack('>I', i) + secret).digest() for i in (0, 1))[:32]
        iv = bytes(16)
        mac_key = hashlib.sha1(b'putty-private-key-file-mac-key' + secret).digest()
        digest = hashlib.sha1
    if encryption != 'none':
        if encryption != 'aes256-cbc':
            raise ValueError('Nieobsługiwane szyfrowanie PPK.')
        dec = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        private = dec.update(private) + dec.finalize()
    public = fields['Public-Lines']
    data = b''.join(string(x) for x in ('ssh-rsa', encryption, fields['Comment'], public, private))
    if not hmac.compare_digest(hmac.new(mac_key, data, digest).hexdigest(), fields['Private-MAC']):
        raise ValueError('Nieprawidłowe hasło klucza lub uszkodzony plik PPK.')
    def read(blob):
        values = []
        while len(blob) >= 4:
            size = struct.unpack('>I', blob[:4])[0]
            if size > len(blob) - 4:
                break
            values.append(blob[4:4+size]); blob = blob[4+size:]
        return values
    parts = read(public)
    e, n = (int.from_bytes(x, 'big') for x in parts[1:3])
    d, p, q, iqmp = (int.from_bytes(x, 'big') for x in read(private)[:4])
    return rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), iqmp, rsa.RSAPublicNumbers(e, n)).private_key()


def as_paramiko(key):
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return paramiko.RSAKey.from_private_key(io.StringIO(pem.decode()))


def load_key(path, password=''):
    p = Path(path)
    if p.stat().st_size > 1024 * 1024:
        raise ValueError('Plik klucza jest zbyt duży.')
    text = p.read_text('utf-8')
    if text.startswith('PuTTY-User-Key-File-'):
        return as_paramiko(ppk_decode(text, password))
    return paramiko.PKey.from_path(p, password=password.encode() if password else None)


def generate(folder, password, comment):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    restrict_folder(folder)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pk = as_paramiko(key)
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    (folder / 'id_rsa').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption))
    (folder / 'id_rsa.ppk').write_text(ppk_encode(key, password, comment), encoding='utf-8')
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + ' ' + comment
    (folder / 'id_rsa.pub').write_text(public + '\n', encoding='utf-8')
    for name in ('id_rsa', 'id_rsa.ppk'):
        if os.name != 'nt':
            (folder / name).chmod(0o600)
    return pk, public, folder


def restrict_folder(folder):
    # Folder is new. Restrict inheritance before writing any private material.
    if os.name == 'nt':
        import subprocess
        sid = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], creationflags=0x08000000).decode(errors='replace').strip().split(',')[-1].strip('"')
        subprocess.run(['icacls', str(folder), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F'], check=True, capture_output=True, creationflags=0x08000000)
    else:
        folder.chmod(0o700)
