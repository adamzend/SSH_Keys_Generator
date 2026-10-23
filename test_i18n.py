# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
import json
from pathlib import Path

def test_gui_languages_and_about(tmp_path,monkeypatch):
    import app,i18n
    monkeypatch.setattr(app,'APP_DATA',tmp_path)
    i18n.set_language('en')
    a=app.App()
    try:
        assert a.auth_list.get()=='Password'
        assert a.mode.get()=='Hasło'
        a.mode.set('Klucz');assert a.auth_list.get()=='Key'
        a.vars['host'].set('example.test')
        a.change_language('pl')
        assert a.auth_list.get()=='Klucz' and a.vars['host'].get()=='example.test'
        a.change_language('en');assert a.auth_list.get()=='Key'
        a.busy=True;a.change_language('pl');assert i18n.LANGUAGE=='en'
        a.busy=False;a.show_about();a.show_help();a.update()
        def labels(w):
            result=[]
            try:result.append(str(w.cget('text')))
            except Exception:pass
            for child in w.winfo_children():result+=labels(child)
            return result
        text='\n'.join(labels(a.about_window))
        assert '(C) Adam Wojcieszonek 2026' in text
        assert 'adam@eksploracja.org.pl' in text
        assert 'https://github.com/adamzend/SSH_Keys_Generator' in text
        assert 'GPL-3.0' in text
        assert 'Connect and check' in labels(a)
        assert 'Połącz i sprawdź' not in labels(a)
    finally:a.destroy()


def test_language_catalogs_match():
    import i18n
    assert set(i18n.CATALOGS['en'])==set(i18n.CATALOGS['pl'])
    assert i18n.CATALOGS['en']['Hasło']=='Password'
    assert all(isinstance(v,str) and v for v in i18n.CATALOGS['en'].values())
