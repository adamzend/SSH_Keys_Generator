# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
import base64
import socket
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
import keys
import remote
from client import Server


@pytest.fixture(scope='module')
def key():
    return rsa.generate_private_key(public_exponent=65537,key_size=3072)


@pytest.mark.parametrize('password',['','test-password-123!','Zażółć-gęślą-123'])
def test_ppk_roundtrip(key,password):
    text=keys.ppk_encode(key,password,'Windows key')
    assert keys.ppk_decode(text,password).private_numbers()==key.private_numbers()


def test_ppk_wrong_password(key):
    with pytest.raises(ValueError,match='hasło'):
        keys.ppk_decode(keys.ppk_encode(key,'right-password','test'),'wrong-password')


def test_ppk_tampering(key):
    text=keys.ppk_encode(key,'secret-password','original').replace('Comment: original','Comment: attacker')
    with pytest.raises(ValueError):keys.ppk_decode(text,'secret-password')


def test_ppk_resource_limit(key):
    text=keys.ppk_encode(key,'secret-password','test').replace('Argon2-Memory: 65536','Argon2-Memory: 999999999')
    with pytest.raises(ValueError,match='limity'):keys.ppk_decode(text,'secret-password')


def test_authorized_keys_options(key):
    pk=keys.as_paramiko(key)
    line='command="echo hello world",no-port-forwarding '+pk.get_name()+' '+pk.get_base64()+' old laptop'
    item=remote.parsed(line)
    assert item['fingerprint']==keys.fingerprint(pk.asbytes())
    assert item['comment']=='old laptop'
    assert 'no-port-forwarding' in item['options']


@pytest.mark.parametrize('line',['# comment','ssh-rsa garbage','-----BEGIN OPENSSH PRIVATE KEY-----','command="ssh-rsa nonsense" invalid'])
def test_reject_invalid_key(line):
    assert remote.parsed(line) is None


def test_changed_snapshot_refused(monkeypatch):
    monkeypatch.setattr(remote,'snapshot',lambda *a:dict(revisions={'file':'new'}))
    with pytest.raises(RuntimeError,match='zmieniła'):
        remote.mutate(dict(action='remove',user='a',address='127.0.0.1',revisions={'file':'old'}))


def test_last_key_refused(monkeypatch):
    state=dict(revisions={},keys=[dict(file='x',line=0,fingerprint='active')])
    monkeypatch.setattr(remote,'snapshot',lambda *a:state)
    monkeypatch.setattr(remote,'account',lambda *a:(None,None,[]))
    with pytest.raises(RuntimeError,match='ostatniego'):
        remote.mutate(dict(action='remove',user='a',address='127.0.0.1',revisions={},file='x',line=0))


def test_active_key_refused(monkeypatch):
    state=dict(revisions={},keys=[dict(file='x',line=0,fingerprint='active'),dict(file='x',line=1,fingerprint='other')])
    monkeypatch.setattr(remote,'snapshot',lambda *a:state)
    monkeypatch.setattr(remote,'account',lambda *a:(None,None,[]))
    with pytest.raises(RuntimeError,match='bieżące'):
        remote.mutate(dict(action='remove',user='a',login='a',address='127.0.0.1',revisions={},file='x',line=0,active_fingerprint='active'))


def test_hardening_requires_first_test():
    events=[]
    fake=SimpleNamespace(test_key=lambda k:(_ for _ in ()).throw(RuntimeError('auth failed')),call=lambda *a,**k:events.append(a))
    with pytest.raises(RuntimeError):Server.disable_passwords(fake,object())
    assert events==[]


def test_hardening_rolls_back_on_second_test():
    events=[];calls=[0]
    def test(k):
        calls[0]+=1
        if calls[0]==2:raise RuntimeError('auth failed')
        return SimpleNamespace(close=lambda:None)
    def call(action,**kwargs):
        events.append(action);return {'token':'test'}
    fake=SimpleNamespace(test_key=test,call=call)
    with pytest.raises(RuntimeError,match='przywracanie'):Server.disable_passwords(fake,object())
    assert events==['harden','abort']


def test_hardening_commit_on_independent_session():
    events=[]
    def call(action,**kwargs):events.append(action);return {'token':'test'}
    probe=SimpleNamespace(close=lambda:None,call=lambda a,**k:events.append('new:'+a))
    fake=SimpleNamespace(test_key=lambda k:probe,call=call)
    Server.disable_passwords(fake,object())
    assert events==['harden','new:commit']


@pytest.mark.parametrize('encrypted',[False,True])
def test_real_putty_reads_generated_ppk(key,tmp_path,encrypted):
    """Independent PuTTY binary authenticates against local throwaway SSH server."""
    plink=Path('C:/Program Files/PuTTY/plink.exe')
    if not plink.exists():pytest.skip('PuTTY not installed')
    password='local-test-passphrase' if encrypted else ''
    path=tmp_path/'test.ppk';path.write_text(keys.ppk_encode(key,password,'test'))
    expected=keys.as_paramiko(key);host=paramiko.RSAKey.generate(2048)
    done=threading.Event();authenticated=[]
    class Handler(paramiko.ServerInterface):
        def get_allowed_auths(self,u):return 'publickey'
        def check_auth_publickey(self,u,k):
            if k==expected:authenticated.append(True);return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
        def check_channel_request(self,kind,chanid):return paramiko.OPEN_SUCCEEDED
        def check_channel_exec_request(self,ch,command):done.set();return True
    sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(1);sock.settimeout(15)
    port=sock.getsockname()[1]
    def serve():
        transport=None
        try:
            conn,_=sock.accept();transport=paramiko.Transport(conn);transport.add_server_key(host);transport.start_server(server=Handler())
            ch=transport.accept(15)
            if ch and done.wait(15):
                ch.send(b'LOCAL_TEST_OK\n');ch.shutdown_write();ch.send_exit_status(0);ch.close()
                deadline=time.time()+5
                while transport.is_active() and time.time()<deadline:time.sleep(.05)
        finally:
            if transport:transport.close()
            sock.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    args=[str(plink),'-ssh','-P',str(port),'-l','test','-i',str(path),'-hostkey',keys.fingerprint(host.asbytes()),'-no-antispoof']
    if not encrypted:args+=['-batch']
    args+=['127.0.0.1','test']
    result=subprocess.run(args,input=password+'\n',capture_output=True,text=True,timeout=25,creationflags=0x08000000)
    thread.join(2)
    assert result.returncode==0,(result.stdout,result.stderr)
    assert 'LOCAL_TEST_OK' in result.stdout and authenticated


def test_generate_files_and_load(tmp_path):
    pk,public,folder=keys.generate(tmp_path/'new-key','long-test-password','test')
    assert keys.load_key(folder/'id_rsa.ppk','long-test-password')==pk
    assert keys.load_key(folder/'id_rsa','long-test-password')==pk
    assert remote.parsed(public)['fingerprint']==keys.fingerprint(pk.asbytes())


def test_remote_add_backup_and_remove_preserves_other_lines(key,tmp_path,monkeypatch):
    home=tmp_path/'home';home.mkdir();target=home/'.ssh/authorized_keys'
    entry=SimpleNamespace(pw_uid=0,pw_gid=0)
    real_path=Path
    def mapped(value):
        if str(value)=='/var/backups/ssh-keys-generator':return tmp_path/'backups'
        return real_path(value)
    monkeypatch.setattr(remote,'Path',mapped)
    monkeypatch.setattr(remote,'account',lambda *a:(entry,{},[target]))
    monkeypatch.setattr(remote,'run',lambda *a,**k:'valid')
    monkeypatch.setattr(remote.os,'chown',lambda *a:None,raising=False)
    monkeypatch.setattr(remote.os,'fchown',lambda *a:None,raising=False)
    pk=keys.as_paramiko(key);public=pk.get_name()+' '+pk.get_base64()+' first'
    state=remote.snapshot('test','127.0.0.1')
    added=remote.mutate(dict(action='add',user='test',address='127.0.0.1',public=public,revisions=state['revisions']))
    assert target.read_text().strip()==public
    assert Path(added['backup']).read_bytes()==b''
    other=paramiko.RSAKey.generate(2048)
    original=target.read_bytes()+b'# preserve this comment\n'+('restrict '+other.get_name()+' '+other.get_base64()+' backup\n').encode()
    target.write_bytes(original)
    state=remote.snapshot('test','127.0.0.1')
    result=remote.mutate(dict(action='remove',user='test',login='admin',address='127.0.0.1',file=str(target),line=0,revisions=state['revisions']))
    assert target.read_bytes().startswith(b'# preserve this comment\nrestrict ')
    assert Path(result['backup']).read_bytes()==original
    assert len(result['keys'])==1


def test_host_key_confirmation_required(tmp_path,monkeypatch):
    import client
    monkeypatch.setattr(client,'APP_DATA',tmp_path)
    fake=paramiko.SSHClient();key=paramiko.RSAKey.generate(2048)
    with pytest.raises(RuntimeError,match='tożsamości'):
        client.TrustPolicy(lambda *a:False).missing_host_key(fake,'example',key)
    assert not (tmp_path/'known_hosts').exists()
    client.TrustPolicy(lambda *a:True).missing_host_key(fake,'example',key)
    assert paramiko.HostKeys(str(tmp_path/'known_hosts')).check('example',key)
