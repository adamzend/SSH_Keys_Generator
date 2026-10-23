# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
import json
import os
import subprocess
from pathlib import Path
import pytest
from profiles import Profiles
from bundles import export_bundle, read_bundle, import_bundle, MAGIC, derive
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASSWORD='A long test phrase 942!'

@pytest.fixture
def sample(tmp_path):
    from keys import generate
    _,_,folder=generate(tmp_path/'original-key','Key passphrase 983!','bundle test')
    key=folder/'id_rsa.ppk'
    source=Profiles(tmp_path/'source')
    for name in ('VPS','Dom żółty'):
        source.save(name,dict(host='example.test',user='user',port='2222',mode='Klucz',key_path=str(key)))
    source.save('Hasło',dict(host='other.test',user='user'))
    package=tmp_path/'test.sshkg'
    export_bundle(source,package,PASSWORD)
    return source,package,key


def test_roundtrip_and_acl(tmp_path,sample):
    source,package,key=sample
    assert b'example.test' not in package.read_bytes()
    assert b'PuTTY-User-Key' not in package.read_bytes()
    other=tmp_path/'other.sshkg';export_bundle(source,other,PASSWORD)
    assert package.read_bytes()!=other.read_bytes()
    target=Profiles(tmp_path/'target');bundle=read_bundle(package,PASSWORD)
    assert import_bundle(target,bundle)==(3,0)
    restored=Path(target.items['VPS']['key_path'])
    assert restored.read_bytes()==key.read_bytes()
    assert target.items['Dom żółty']['key_path']==str(restored)
    assert target.items['Hasło']['key_path']==''
    assert restored.is_relative_to(tmp_path/'target'/'imported_keys')
    if os.name=='nt':
        acl=subprocess.check_output(['icacls',str(restored.parent)],creationflags=0x08000000).decode(errors='replace')
        assert '(I)' not in acl and '(OI)(CI)(F)' in acl
    else:assert restored.stat().st_mode & 0o777 == 0o600
    assert import_bundle(target,bundle)==(0,3)
    assert import_bundle(target,bundle,True)==(3,0)
    assert Path(target.items['VPS']['key_path'])!=restored and restored.exists()


def test_wrong_password_tamper_and_truncation(tmp_path,sample):
    _,package,_=sample
    with pytest.raises(ValueError,match='hasło'):read_bundle(package,'wrong password 123')
    original=package.read_bytes()
    for offset in (len(MAGIC),len(MAGIC)+16,len(original)-1):
        changed=bytearray(original);changed[offset]^=1;package.write_bytes(changed)
        with pytest.raises(ValueError):read_bundle(package,PASSWORD)
    package.write_bytes(original[:15])
    with pytest.raises(ValueError):read_bundle(package,PASSWORD)
    assert not (tmp_path/'target').exists()


def test_export_failures_preserve_files(tmp_path,sample):
    source,package,key=sample
    original=package.read_bytes();key_before=key.read_bytes()
    with pytest.raises(ValueError):export_bundle(source,key,PASSWORD)
    assert key.read_bytes()==key_before
    with pytest.raises(ValueError):export_bundle(source,package,'short')
    source.save('Missing',dict(host='example.test',user='me',mode='Klucz',key_path=str(tmp_path/'missing')))
    with pytest.raises(OSError):export_bundle(source,package,PASSWORD)
    assert package.read_bytes()==original


def test_import_rollback(tmp_path,sample,monkeypatch):
    _,package,_=sample;target=Profiles(tmp_path/'target')
    target.save('Existing',dict(host='old',user='me'));before=target.path.read_bytes()
    def fail(*a,**kw):raise OSError('test write failure')
    monkeypatch.setattr(target,'merge',fail)
    with pytest.raises(OSError):import_bundle(target,read_bundle(package,PASSWORD))
    assert target.path.read_bytes()==before
    assert list((target.path.parent/'imported_keys').iterdir())==[]


def test_authenticated_invalid_reference_rejected(tmp_path,sample):
    _,package,_=sample
    blob=package.read_bytes();length=len(MAGIC)+28;header=blob[:length]
    key=derive(PASSWORD,header[len(MAGIC):len(MAGIC)+16]);nonce=header[-12:]
    data=json.loads(AESGCM(key).decrypt(nonce,blob[length:],header))
    data['refs']['VPS']='../../outside'
    package.write_bytes(header+AESGCM(key).encrypt(nonce,json.dumps(data).encode(),header))
    with pytest.raises(ValueError):read_bundle(package,PASSWORD)


def test_acl_failure_writes_no_keys(tmp_path,sample,monkeypatch):
    import bundles
    _,package,_=sample;target=Profiles(tmp_path/'target')
    def fail(folder):raise OSError('ACL denied')
    monkeypatch.setattr(bundles,'restrict_folder',fail)
    with pytest.raises(OSError):import_bundle(target,read_bundle(package,PASSWORD))
    assert not target.path.exists()
    assert list((target.path.parent/'imported_keys').iterdir())==[]


def test_gui_bundle_import_disconnects(tmp_path,sample,monkeypatch):
    import app
    from unittest.mock import Mock
    _,package,_=sample
    monkeypatch.setattr(app,'APP_DATA',tmp_path/'gui')
    monkeypatch.setattr(app.messagebox,'showinfo',lambda *a,**kw:None)
    monkeypatch.setattr(app.messagebox,'askyesnocancel',lambda *a,**kw:True)
    a=app.App()
    try:
        a.profiles.save('VPS',dict(host='old',user='old'));a.apply_profile('VPS')
        a.server=Mock();server=a.server
        a.task=lambda label,work,done:done(work())
        a.finish_bundle_import(read_bundle(package,PASSWORD))
        server.close.assert_called_once()
        assert a.server is None
        assert Path(a.vars['key_path'].get()).is_file()
    finally:a.destroy()
