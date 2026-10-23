# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
import json
from unittest.mock import Mock
import pytest
from profiles import Profiles


def test_profiles_roundtrip_and_no_secrets(tmp_path):
    p=Profiles(tmp_path)
    p.save('Dom żółty',dict(host='home',user='me',port='2222',password='SECRET',passphrase='SECRET',sudo_password='SECRET',key_path='C:/key.ppk',mode='Klucz'))
    p.save('VPS',dict(host='vps',user='admin'))
    assert 'SECRET' not in p.path.read_text('utf-8')
    q=Profiles(tmp_path)
    assert len(q.items)==2 and q.selected=='VPS'
    assert q.items['Dom żółty']['port']=='2222'
    q.delete('VPS')
    assert list(Profiles(tmp_path).items)==['Dom żółty']


def test_migration_and_corruption_preserved(tmp_path):
    (tmp_path/'last_connection.json').write_text(json.dumps(dict(host='old',key_path='key.ppk')))
    p=Profiles(tmp_path)
    assert p.items[p.selected]['mode']=='Klucz'
    p.path.write_text('broken')
    with pytest.raises(ValueError):Profiles(tmp_path)
    assert p.path.read_text()=='broken'


def test_profile_switch_disconnects_and_busy_guard(tmp_path,monkeypatch):
    import app
    monkeypatch.setattr(app,'APP_DATA',tmp_path)
    a=app.App()
    try:
        a.profiles.save('VPS',dict(host='vps',user='me'))
        a.server=Mock();old=a.server
        a.vars['password'].set('secret');a.disable_pw.set(True)
        a.profile_name.set('VPS');a.select_profile()
        old.close.assert_called_once()
        assert a.server is None and a.vars['password'].get()==''
        assert not a.disable_pw.get() and a.vars['host'].get()=='vps'
        a.busy=True;a.profile_name.set('other');a.select_profile()
        assert a.profile_name.get()=='VPS' and a.vars['host'].get()=='vps'
        a.show_help();a.update()
        assert a.help_window.winfo_exists()
    finally:a.destroy()

from profiles import read_export


def test_export_import_roundtrip_and_conflicts(tmp_path):
    source=Profiles(tmp_path/'source')
    source.save('Dom żółty',dict(host='home',user='me',port='2222',key_path='C:/key.ppk',mode='Klucz',password='SECRET'))
    file=tmp_path/'export.json'
    source.export_file(file)
    assert 'SECRET' not in file.read_text('utf-8')
    target=Profiles(tmp_path/'target')
    target.save('Dom żółty',dict(host='old',user='me'))
    incoming=read_export(file)
    assert target.merge(incoming)==(0,1)
    assert target.items['Dom żółty']['host']=='old'
    assert target.merge(incoming,True)==(1,0)
    assert Profiles(tmp_path/'target').items==source.items
    with pytest.raises(ValueError):source.export_file(source.path)


@pytest.mark.parametrize('change',[
    lambda d:d.update(version=99),
    lambda d:d['profiles']['VPS'].update(port='0'),
    lambda d:d['profiles']['VPS'].update(mode='other'),
    lambda d:d['profiles']['VPS'].update(host=['host']),
    lambda d:d['profiles'].update(Broken={}),
])
def test_invalid_import_is_rejected(tmp_path,change):
    p=Profiles(tmp_path/'store');p.save('VPS',dict(host='vps',user='admin'))
    f=tmp_path/'export.json';p.export_file(f)
    before=p.path.read_bytes()
    data=json.loads(f.read_text('utf-8'));change(data)
    f.write_text(json.dumps(data),'utf-8')
    with pytest.raises(ValueError):p.merge(read_export(f),True)
    assert p.path.read_bytes()==before


def test_gui_import_cancel_and_replace_disconnect(tmp_path,monkeypatch):
    import app
    monkeypatch.setattr(app,'APP_DATA',tmp_path/'target')
    source=Profiles(tmp_path/'source');source.save('VPS',dict(host='new',user='me'))
    f=tmp_path/'export.json';source.export_file(f)
    monkeypatch.setattr(app.filedialog,'askopenfilename',lambda **kw:str(f))
    monkeypatch.setattr(app.messagebox,'showinfo',lambda *a,**kw:None)
    a=app.App()
    try:
        a.profiles.save('VPS',dict(host='old',user='me'));a.apply_profile('VPS')
        a.server=Mock();old=a.server
        monkeypatch.setattr(app.messagebox,'askyesnocancel',lambda *args,**kw:None)
        a.import_profiles()
        assert a.server is old and a.profiles.items['VPS']['host']=='old'
        monkeypatch.setattr(app.messagebox,'askyesnocancel',lambda *args,**kw:True)
        a.import_profiles()
        old.close.assert_called_once()
        assert a.server is None and a.vars['host'].get()=='new'
    finally:a.destroy()
