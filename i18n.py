# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""JSON language catalogs; persisted authentication values stay language-neutral."""
import json
import sys
from pathlib import Path
from tkinter import messagebox as native_messagebox

RESOURCE_DIR=Path(getattr(sys,'_MEIPASS',Path(__file__).parent))
CATALOGS={lang:json.loads((RESOURCE_DIR/'locales'/f'{lang}.json').read_text('utf-8')) for lang in ('en','pl')}
LANGUAGE='en'

def set_language(lang):
    global LANGUAGE
    if lang not in CATALOGS:raise ValueError('Unsupported language')
    LANGUAGE=lang

def tr(text):
    return CATALOGS[LANGUAGE].get(text,text)

def translate_message(text):
    if not isinstance(text,str):return text
    catalog=CATALOGS[LANGUAGE]
    if text in catalog:return catalog[text]
    # Backend errors may append a user-controlled path/name. Translate only the prefix.
    for source in sorted(catalog,key=len,reverse=True):
        if len(source)>12 and source.endswith((': ','. ')) and text.startswith(source):
            return catalog[source]+text[len(source):]
    return text

class Messages:
    def __getattr__(self,name):
        func=getattr(native_messagebox,name)
        def call(*args,**kwargs):
            args=tuple(translate_message(v) if i<2 else v for i,v in enumerate(args))
            for key in ('title','message','detail'):
                if key in kwargs:kwargs[key]=translate_message(kwargs[key])
            return func(*args,**kwargs)
        return call

messagebox=Messages()
