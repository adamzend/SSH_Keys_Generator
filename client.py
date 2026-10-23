# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
import base64
import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

import paramiko
from keys import load_key, fingerprint


APP_DATA = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'SSH_Keys_Generator'


@dataclass
class Connection:
    host: str
    port: int
    user: str
    password: str = ''
    key_path: str = ''
    passphrase: str = ''
    sudo_password: str = ''


class TrustPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, confirm):
        self.confirm = confirm

    def missing_host_key(self, client, hostname, key):
        if not self.confirm(hostname, key.get_name(), fingerprint(key.asbytes())):
            raise RuntimeError('Nie zaakceptowano tożsamości serwera.')
        client.get_host_keys().add(hostname, key.get_name(), key)
        APP_DATA.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(APP_DATA / 'known_hosts'))


class Server:
    def __init__(self, config, confirm, pkey=None):
        self.config = config
        self.confirm = confirm
        self.client = paramiko.SSHClient()
        known = APP_DATA / 'known_hosts'
        if known.exists():
            self.client.load_host_keys(str(known))
        self.client.set_missing_host_key_policy(TrustPolicy(confirm))
        self.key = pkey or (load_key(config.key_path, config.passphrase) if config.key_path else None)
        self.client.connect(config.host, port=config.port, username=config.user,
                            password=None if self.key else config.password, pkey=self.key,
                            look_for_keys=False, allow_agent=False, timeout=15,
                            banner_timeout=20, auth_timeout=25, channel_timeout=30)
        self.client.get_transport().set_keepalive(20)
        self.hostkey = self.client.get_transport().get_remote_server_key()
        self.address = self.command('printf "%s" "$SSH_CONNECTION"')[0].split()[0]
        self.active_fp = fingerprint(self.key.asbytes()) if self.key else ''

    def close(self):
        self.client.close()

    def command(self, command, password=None):
        stdin, stdout, stderr = self.client.exec_command(command, timeout=40)
        if password is not None:
            stdin.write(password + '\n'); stdin.flush()
        stdin.channel.shutdown_write()
        out, err = stdout.read().decode('utf-8', 'replace'), stderr.read().decode('utf-8', 'replace')
        code = stdout.channel.recv_exit_status()
        if code:
            raise RuntimeError((err or out or 'Polecenie zakończyło się błędem.')[-2000:])
        return out, err

    def call(self, action, user=None, **values):
        req = dict(action=action, user=user or self.config.user, address=self.address,
                   login=self.config.user, active_fingerprint=self.active_fp, **values)
        helper = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'remote.py'
        source = base64.b64encode(helper.read_bytes()).decode()
        code = 'import base64;exec(compile(base64.b64decode(' + repr(source) + '),"sshkeys-helper","exec"))'
        payload = base64.b64encode(json.dumps(req).encode()).decode()
        cmd = 'python3 -c ' + shlex.quote(code) + ' ' + shlex.quote(payload)
        password = None
        if self.config.user != 'root':
            # Test NOPASSWD first, without sending a password that could become helper input.
            try:
                self.command('sudo -n true')
                cmd = 'sudo -n -- ' + cmd
            except RuntimeError:
                password = self.config.sudo_password or self.config.password
                if not password:
                    raise RuntimeError('Podaj hasło sudo. Nie zapisujemy go na dysku.')
                cmd = "sudo -S -p '' -- " + cmd
        try:
            out, _ = self.command(cmd, password)
        except RuntimeError as e:
            try:
                response = json.loads(str(e))
                raise RuntimeError(response.get('error', 'Błąd serwera')) from None
            except json.JSONDecodeError:
                raise e
        response = json.loads(out)
        if not response['ok']:
            raise RuntimeError(response['error'])
        return response['result']

    def test_key(self, key):
        other = Server(self.config, self.confirm, pkey=key)
        other.command('true')
        return other

    def disable_passwords(self, key):
        # Same login account, explicitly key-only authentication, independent transport.
        probe = self.test_key(key)
        probe.close()
        transaction = self.call('harden')
        try:
            verified = self.test_key(key)
            try:
                verified.call('commit', token=transaction['token'])
            finally:
                verified.close()
        except Exception:
            try:
                self.call('abort', token=transaction['token'])
            except Exception:
                pass  # The independently scheduled 150-second rollback remains armed.
            raise RuntimeError('Nie potwierdzono nowego połączenia. Uruchomiono przywracanie konfiguracji; jeśli połączenie zniknęło, odczekaj 150 sekund.') from None
        return transaction
