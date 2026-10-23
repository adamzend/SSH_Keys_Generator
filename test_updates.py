# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
import hashlib
import io
import json
from dataclasses import replace
from urllib.error import HTTPError, URLError
import pytest
import updates

PAYLOAD=b'MZ-test-installer-bytes'

def metadata():
    return dict(tag_name='v1.10.0',draft=False,prerelease=False,assets=[dict(
        name=updates.INSTALLER,state='uploaded',size=len(PAYLOAD),
        digest='sha256:'+hashlib.sha256(PAYLOAD).hexdigest(),
        browser_download_url=updates.REPOSITORY_URL+'/releases/download/v1.10.0/'+updates.INSTALLER)])


def release(monkeypatch):
    monkeypatch.setattr(updates,'open_url',lambda url:io.BytesIO(json.dumps(metadata()).encode()))
    return updates.check_latest()


def test_version_comparison():
    assert updates.version_tuple('v1.10.0')>updates.version_tuple('1.9.99')
    assert updates.version_tuple('1.5.0')==updates.version_tuple('v1.5.0')
    for bad in ('1.5','1.5.0-beta','../../1.0.0',None):
        with pytest.raises(ValueError):updates.version_tuple(bad)


@pytest.mark.parametrize('change',[
    lambda d:d.update(draft=True),lambda d:d.update(prerelease=True),
    lambda d:d.update(tag_name='v2.0.0-beta'),lambda d:d.update(assets=[]),
    lambda d:d['assets'][0].update(digest=None),
    lambda d:d['assets'][0].update(browser_download_url='https://example.test/setup.exe'),
    lambda d:d['assets'][0].update(size=updates.MAX_INSTALLER+1),
])
def test_reject_invalid_metadata(monkeypatch,change):
    data=metadata();change(data)
    monkeypatch.setattr(updates,'open_url',lambda url:io.BytesIO(json.dumps(data).encode()))
    with pytest.raises(ValueError):updates.check_latest()


@pytest.mark.parametrize('url',['http://github.com/a','https://github.com.evil.test/a','file:///tmp/a','https://user:pass@github.com/a','https://github.com:8080/a'])
def test_redirect_restrictions(url):
    with pytest.raises(ValueError):updates.validate_url(url)
    with pytest.raises(ValueError):updates.SafeRedirect().redirect_request(None,None,302,'',{},url)


def test_verified_download(monkeypatch,tmp_path):
    info=release(monkeypatch)
    monkeypatch.setattr(updates,'open_url',lambda url:io.BytesIO(PAYLOAD))
    target=tmp_path/'installer.exe'
    assert updates.download_installer(info,target)==target
    assert target.read_bytes()==PAYLOAD
    assert list(tmp_path.iterdir())==[target]


@pytest.mark.parametrize('body',[b'changed',PAYLOAD[:-1],PAYLOAD+b'EXTRA',b'NZ'+PAYLOAD[2:]])
def test_failed_download_preserves_existing_file(monkeypatch,tmp_path,body):
    info=release(monkeypatch)
    monkeypatch.setattr(updates,'open_url',lambda url:io.BytesIO(body))
    target=tmp_path/'installer.exe';target.write_bytes(b'keep')
    with pytest.raises(ValueError):updates.download_installer(info,target)
    assert target.read_bytes()==b'keep'
    assert list(tmp_path.iterdir())==[target]


def test_network_error_and_rate_limit(monkeypatch):
    class Opener:
        def open(self,*args,**kwargs):raise URLError('offline')
    monkeypatch.setattr(updates,'build_opener',lambda *args:Opener())
    with pytest.raises(ValueError,match='internet'):updates.check_latest()
    class RateLimited:
        def open(self,*args,**kwargs):raise HTTPError(updates.API_URL,403,'limit',{},None)
    monkeypatch.setattr(updates,'build_opener',lambda *args:RateLimited())
    with pytest.raises(ValueError,match='zapyt'):updates.check_latest()


def test_gui_update_offer_cancel_current_and_old(tmp_path,monkeypatch):
    import app,i18n
    monkeypatch.setattr(app,'APP_DATA',tmp_path)
    i18n.set_language('en')
    info=release(monkeypatch)
    prompts=[];downloads=[];messages=[]
    monkeypatch.setattr(app.messagebox,'askyesno',lambda title,text,**kw:prompts.append(text) or False)
    monkeypatch.setattr(app.messagebox,'showinfo',lambda title,text,**kw:messages.append(text))
    monkeypatch.setattr(app,'download_installer',lambda *args:downloads.append(args))
    a=app.App()
    try:
        a.offer_update(info)
        assert 'new version' in prompts[-1]
        a.offer_update(replace(info,version=app.VERSION))
        assert 'latest version' in prompts[-1]
        a.offer_update(replace(info,version='1.0.0'))
        assert 'newer' in messages[-1] and len(prompts)==2
        assert not downloads
        a.busy=True
        a.task=lambda *args:pytest.fail('busy application must not check for updates')
        a.check_updates()
    finally:a.destroy()
