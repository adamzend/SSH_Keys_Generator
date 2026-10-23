# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""Privileged Linux helper. Only public keys and transaction IDs enter requests."""
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path


def run(args, **kwargs):
    p = subprocess.run(args, capture_output=True, text=True, timeout=25, **kwargs)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or 'Błąd polecenia')[-2000:])
    return p.stdout


def parsed(line):
    try:
        parts = shlex.split(line, comments=True)
        for i, word in enumerate(parts[:-1]):
            if word.startswith(('ssh-', 'ecdsa-', 'sk-')):
                blob = base64.b64decode(parts[i+1], validate=True)
                n = int.from_bytes(blob[:4], 'big')
                if blob[4:4+n].decode() != word:
                    continue
                fp = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
                return dict(kind=word, fingerprint=fp, comment=' '.join(parts[i+2:]), options=' '.join(parts[:i]))
    except (ValueError, UnicodeError):
        pass
    return None


def safe_path(path):
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise RuntimeError('Odmowa zmiany ścieżki będącej dowiązaniem: ' + str(part))
    if path.exists() and not path.is_file():
        raise RuntimeError('Ścieżka nie jest zwykłym plikiem: ' + str(path))


def settings(user, address):
    sshd = shutil.which('sshd') or '/usr/sbin/sshd'
    out = run([sshd, '-T', '-C', 'user=' + user + ',host=localhost,addr=' + address])
    return dict(l.split(' ', 1) for l in out.splitlines() if ' ' in l)


def account(user, address):
    import pwd
    entry = pwd.getpwnam(user)
    cfg = settings(user, address)
    if cfg.get('authorizedkeyscommand', 'none') != 'none':
        raise RuntimeError('Serwer pobiera klucze przez AuthorizedKeysCommand. Ta wersja nie zarządza tym źródłem.')
    home = Path(entry.pw_dir)
    if not home.is_absolute() or home == Path('/') or not home.is_dir():
        raise RuntimeError('Nieobsługiwany katalog domowy konta.')
    paths = []
    for value in cfg.get('authorizedkeysfile', '.ssh/authorized_keys').split():
        if value == 'none':
            continue
        value = value.replace('%h', str(home)).replace('%u', user).replace('%U', str(entry.pw_uid))
        if '%' in value:
            raise RuntimeError('Nieobsługiwany token AuthorizedKeysFile.')
        p = Path(value) if value.startswith('/') else home / value
        p = Path(os.path.abspath(p))
        if not p.is_relative_to(home) or p == home:
            raise RuntimeError('Ta wersja zarządza wyłącznie plikami kluczy wewnątrz katalogu domowego użytkownika.')
        safe_path(p)
        paths.append(p)
    if not paths:
        raise RuntimeError('Brak obsługiwanego pliku AuthorizedKeysFile.')
    return entry, cfg, list(dict.fromkeys(paths))


def snapshot(user, address):
    entry, cfg, paths = account(user, address)
    rows, revisions = [], {}
    for p in paths:
        if p.exists() and p.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('Plik authorized_keys jest nietypowo duży.')
        data = p.read_bytes() if p.exists() else b''
        revisions[str(p)] = hashlib.sha256(data).hexdigest()
        for i, line in enumerate(data.decode('utf-8', errors='surrogateescape').splitlines()):
            item = parsed(line)
            if item:
                rows.append(dict(item, file=str(p), line=i, raw=line))
    return dict(user=user, keys=rows, revisions=revisions,
                password=cfg.get('passwordauthentication'), keyboard=cfg.get('kbdinteractiveauthentication'),
                pubkey=cfg.get('pubkeyauthentication'), ca=cfg.get('trustedusercakeys', 'none'),
                paths=[str(p) for p in paths])


def atomic(path, data, uid=0, gid=0, mode=0o600):
    safe_path(path)
    temp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def mutate(req):
    user, address = req['user'], req['address']
    current = snapshot(user, address)
    if current['revisions'] != req['revisions']:
        raise RuntimeError('Lista kluczy zmieniła się na serwerze. Odśwież ją przed zmianą.')
    entry, _, paths = account(user, address)
    if req['action'] == 'add':
        line = req['public'].strip()
        if '\n' in line or '\r' in line or not parsed(line) or parsed(line)['options']:
            raise RuntimeError('Wklej jeden klucz publiczny OpenSSH, bez dodatkowych opcji.')
        run(['ssh-keygen', '-l', '-f', '/dev/stdin'], input=line + '\n')
        fp = parsed(line)['fingerprint']
        if any(k['fingerprint'] == fp for k in current['keys']):
            raise RuntimeError('Ten klucz jest już dodany.')
        target = paths[0]
        old = target.read_bytes() if target.exists() else b''
        new = old + (b'\n' if old and not old.endswith(b'\n') else b'') + line.encode() + b'\n'
    else:
        found = [k for k in current['keys'] if k['file'] == req['file'] and k['line'] == req['line']]
        if len(found) != 1:
            raise RuntimeError('Nie odnaleziono wybranego klucza.')
        if len(current['keys']) <= 1:
            raise RuntimeError('Nie można usunąć ostatniego klucza konta. Najpierw dodaj i przetestuj inny.')
        if user == req['login'] and found[0]['fingerprint'] == req.get('active_fingerprint'):
            raise RuntimeError('Nie można usunąć klucza używanego przez bieżące połączenie.')
        target = Path(req['file'])
        if target not in paths:
            raise RuntimeError('Nieprawidłowa ścieżka.')
        old = target.read_bytes()
        lines = old.splitlines(keepends=True)
        del lines[req['line']]
        new = b''.join(lines)
    # Never repair ownership of existing shared directories implicitly.
    if not target.parent.exists():
        target.parent.mkdir(mode=0o700, parents=True)
        os.chown(target.parent, entry.pw_uid, entry.pw_gid)
    safe_path(target)
    backup_dir = Path('/var/backups/ssh-keys-generator')
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup = backup_dir / (time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex + '.authorized_keys')
    atomic(backup, old)
    # Recheck immediately before atomic replacement (external edits are not overwritten silently).
    if (target.read_bytes() if target.exists() else b'') != old:
        raise RuntimeError('Plik został zmieniony równolegle. Odśwież listę.')
    atomic(target, new, entry.pw_uid, entry.pw_gid)
    return dict(snapshot(user, address), backup=str(backup))


def harden(req):
    """systemd rollback is armed BEFORE changing sshd. Caller verifies a NEW key-only session."""
    if not shutil.which('systemd-run'):
        raise RuntimeError('Automatyczny powrót wymaga systemd. Hasła nie zostały wyłączone.')
    main = Path('/etc/ssh/sshd_config')
    safe_path(main)
    # Match/complex includes require administrator-specific analysis; fail closed.
    sources = [main, *Path('/etc/ssh/sshd_config.d').glob('*.conf')]
    for p in sources:
        for line in p.read_text().splitlines():
            tokens = line.strip().split()
            if not tokens or tokens[0].startswith('#'):
                continue
            if tokens[0].lower() == 'match':
                raise RuntimeError('Konfiguracja zawiera sekcję Match. Automatyczne wyłączenie haseł wymaga ręcznej analizy administratora.')
            if tokens[0].lower() == 'include' and tokens[1:] != ['/etc/ssh/sshd_config.d/*.conf']:
                raise RuntimeError('Niestandardowe Include SSH: wymagany ręczny przegląd konfiguracji.')
    sshd = shutil.which('sshd') or '/usr/sbin/sshd'
    run([sshd, '-t'])
    service = next((s for s in ['ssh', 'sshd'] if subprocess.run(['systemctl', 'is-active', '--quiet', s]).returncode == 0), None)
    if not service:
        raise RuntimeError('Nie odnaleziono aktywnej usługi SSH.')
    token = uuid.uuid4().hex
    unit = 'sshkeys-rollback-' + token
    root = Path('/var/lib/ssh-keys-generator'); root.mkdir(mode=0o700, exist_ok=True)
    txn = root / token; txn.mkdir(mode=0o700)
    block = ('# SSH_Keys_Generator BEGIN ' + token + '\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPubkeyAuthentication yes\n# SSH_Keys_Generator END\n').encode()
    original = main.read_bytes()
    atomic(txn / 'sshd_config.before', original)
    rollback = """import pathlib,subprocess,os
p=pathlib.Path('/etc/ssh/sshd_config')
block=bytes.fromhex(BLOCK)
data=p.read_bytes()
if data.startswith(block):
    tmp=p.with_name('.sshkeys-restore')
    st=p.stat()
    with open(tmp,'wb') as f: f.write(data[len(block):]); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,st.st_mode & 0o777);os.chown(tmp,st.st_uid,st.st_gid);os.replace(tmp,p)
    subprocess.run([SSHD,'-t'],check=True)
    subprocess.run(['systemctl','reload',SERVICE],check=True)
pathlib.Path(MARKER).touch()
""".replace('BLOCK', repr(block.hex())).replace('SSHD', repr(sshd)).replace('SERVICE', repr(service)).replace('MARKER', repr(str(txn / 'rolled-back')))
    atomic(txn / 'rollback.py', rollback.encode())
    meta = dict(unit=unit, deadline=time.time()+150, block=block.hex(), user=req['user'], address=req['address'])
    atomic(txn / 'meta.json', json.dumps(meta).encode())
    run(['systemd-run', '--unit=' + unit, '--on-active=150s', '--timer-property=AccuracySec=1s', sys.executable, str(txn / 'rollback.py')])
    try:
        st = main.stat()
        atomic(main, block + original, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
        run([sshd, '-t'])
        run(['systemctl', 'reload', service])
        cfg = settings(req['user'], req['address'])
        if cfg.get('passwordauthentication') != 'no' or cfg.get('kbdinteractiveauthentication') != 'no':
            raise RuntimeError('Efektywna konfiguracja nadal dopuszcza hasła.')
    except Exception:
        run([sys.executable, str(txn / 'rollback.py')])
        run(['systemctl', 'stop', unit + '.timer'])
        raise
    return dict(token=token, backup=str(txn / 'sshd_config.before'), deadline=meta['deadline'])


def finish(req):
    token = req['token']
    if not re.fullmatch('[a-f0-9]{32}', token):
        raise RuntimeError('Nieprawidłowa transakcja.')
    txn = Path('/var/lib/ssh-keys-generator') / token
    meta = json.loads((txn / 'meta.json').read_text())
    if req['action'] == 'abort':
        run([sys.executable, str(txn / 'rollback.py')])
        run(['systemctl', 'stop', meta['unit'] + '.timer'])
        return dict(restored=True)
    if time.time() > meta['deadline']-15 or (txn / 'rolled-back').exists():
        raise RuntimeError('Upłynął czas weryfikacji. Konfiguracja wróci automatycznie.')
    if not Path('/etc/ssh/sshd_config').read_bytes().startswith(bytes.fromhex(meta['block'])):
        raise RuntimeError('Konfiguracja SSH została zmieniona. Nie można zatwierdzić.')
    run(['systemctl', 'stop', meta['unit'] + '.timer'])
    return dict(committed=True)


def main(req):
    if os.geteuid() != 0:
        raise RuntimeError('Wymagane uprawnienia root / sudo do audytu konfiguracji SSH.')
    import fcntl
    lock_dir = Path('/run/ssh-keys-generator'); lock_dir.mkdir(mode=0o700, exist_ok=True)
    with (lock_dir / 'lock').open('w') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        action = req['action']
        if action == 'list':
            return snapshot(req['user'], req['address'])
        if action in ('add', 'remove'):
            return mutate(req)
        if action == 'harden':
            return harden(req)
        if action in ('commit', 'abort'):
            return finish(req)
        if action == 'users':
            import pwd
            return dict(users=[p.pw_name for p in pwd.getpwall() if (p.pw_uid >= 1000 or p.pw_uid == 0) and p.pw_shell.endswith(('/bash','/sh','/zsh','/fish'))])
        raise RuntimeError('Nieznana operacja.')


if __name__ == '__main__':
    try:
        request = json.loads(base64.b64decode(sys.argv[1]))
        print(json.dumps(dict(ok=True, result=main(request))))
    except Exception as e:
        print(json.dumps(dict(ok=False, error=str(e))))
        sys.exit(1)
