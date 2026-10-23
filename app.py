# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""SSH_Keys_Generator — Windows desktop GUI (Polish)."""
import datetime
import webbrowser
import sys
import os
import queue
import subprocess
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import i18n
from i18n import tr, translate_message, messagebox, RESOURCE_DIR
from version import VERSION, REPOSITORY_URL, COPYRIGHT, CONTACT, LICENSE_NAME

from client import APP_DATA, Connection, Server
from keys import generate, fingerprint
from profiles import Profiles, FIELDS, read_export
from bundles import export_bundle, read_bundle, import_bundle
from updates import check_latest, download_installer, version_tuple


class AuthVariable(tk.StringVar):
    def __init__(self, value, **kwargs):
        super().__init__(value=tr(value), **kwargs)
    def set(self,value):
        super().set(tr(value))
    def get(self):
        value=super().get()
        return {'Password':'Hasło','Key':'Klucz'}.get(value,value)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('SSH_Keys_Generator')
        self.geometry('1120x860'); self.minsize(980, 650)
        self.configure(bg='#f1f5f9')
        self.server = None; self.state = None; self.busy = False
        self.events = queue.Queue(); self.actions = []
        self.generated_key = None; self.generated_folder = None
        style = ttk.Style(self); style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 10))
        style.configure('TFrame', background='#f1f5f9')
        style.configure('TLabel', background='#f1f5f9')
        style.configure('TLabelframe', background='#f1f5f9')
        style.configure('TLabelframe.Label', background='#f1f5f9', font=('Segoe UI', 10, 'bold'))
        style.configure('TButton', padding=(10, 6))
        style.configure('Accent.TButton', background='#155e75', foreground='white')
        style.map('Accent.TButton', background=[('active', '#0e7490')])
        self.vars = {k: tk.StringVar(value=v) for k,v in dict(host='',port='22',user='',password='',key_path='',passphrase='',sudo_password='',target='',new_pass='',confirm_pass='',folder=str(Path.home()/'SSH_Keys'),comment='Windows SSH key').items()}
        self.mode = AuthVariable(value='Hasło'); self.disable_pw = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value=tr('Niepołączony • zmiany na serwerze wymagają świadomego uruchomienia operacji'))
        self.count = tk.StringVar(value=tr('Połącz się, aby odczytać klucze wybranego konta.'))
        canvas=tk.Canvas(self,bg='#f1f5f9',highlightthickness=0)
        page_scroll=ttk.Scrollbar(self,orient='vertical',command=canvas.yview)
        canvas.configure(yscrollcommand=page_scroll.set)
        page_scroll.pack(side='right',fill='y');canvas.pack(side='left',fill='both',expand=True)
        outer = ttk.Frame(canvas, padding=20)
        page=canvas.create_window((0,0),window=outer,anchor='nw')
        outer.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(page,width=e.width))
        self.bind('<MouseWheel>',lambda e:canvas.yview_scroll(int(-e.delta/120),'units') if e.widget.winfo_class() not in ('Text','Treeview') else None)
        ttk.Label(outer, text='SSH_Keys_Generator', font=('Segoe UI', 22, 'bold'), foreground='#0f172a').pack(anchor='w')
        ttk.Label(outer, text=tr('Klucze PuTTY • zarządzanie dostępem • kontrolowane wyłączanie haseł'), foreground='#475569').pack(anchor='w', pady=(2,14))
        header=ttk.Frame(outer);header.pack(fill='x',pady=(0,8))
        self.flag_images={lang:tk.PhotoImage(file=str(RESOURCE_DIR/'assets'/f'{lang}.png')) for lang in ('en','pl')}
        for lang,label in [('en','English'),('pl','Polski')]:
            self.button(header,label,lambda code=lang:self.change_language(code)).pack(side='left',padx=(0,8))
            self.actions[-1].configure(image=self.flag_images[lang],compound='left')
        ttk.Button(header,text='About',command=self.show_about).pack(side='right')
        ttk.Button(header,text=tr('Instrukcja'),command=self.show_help).pack(side='right',padx=8)
        self.button(header,tr('Sprawdź aktualizacje'),self.check_updates).pack(side='right',padx=8)
        self.about_window=None
        self.profile_name=tk.StringVar()
        self.active_profile=''
        self.profiles=None
        self.help_window=None
        profiles_bar=ttk.Frame(outer);profiles_bar.pack(fill='x',pady=(0,10))
        ttk.Label(profiles_bar,text=tr('Profil serwera:')).pack(side='left')
        self.profile_list=ttk.Combobox(profiles_bar,textvariable=self.profile_name,state='readonly',width=36)
        self.profile_list.pack(side='left',padx=8)
        self.profile_list.bind('<<ComboboxSelected>>',self.select_profile)
        self.button(profiles_bar,tr('Zapisz profil…'),self.save_profile).pack(side='left')
        self.button(profiles_bar,tr('Nowy'),self.new_profile).pack(side='left',padx=8)
        self.button(profiles_bar,tr('Usuń profil'),self.delete_profile).pack(side='left')
        transfer_bar=ttk.Frame(outer);transfer_bar.pack(fill='x',pady=(0,10))
        self.button(transfer_bar,tr('Eksportuj profile…'),self.export_profiles).pack(side='left')
        self.button(transfer_bar,tr('Importuj profile…'),self.import_profiles).pack(side='left',padx=8)
        self.button(transfer_bar,tr('Eksportuj z kluczami…'),self.export_with_keys).pack(side='left',padx=8)
        self.button(transfer_bar,tr('Importuj z kluczami…'),self.import_with_keys).pack(side='left')
        conn = ttk.LabelFrame(outer, text=tr('1. Połączenie z serwerem'), padding=12); conn.pack(fill='x')
        for i in range(6): conn.columnconfigure(i, weight=1 if i % 2 else 0)
        self.field(conn,tr('Adres IP / host'),'host',0,0,26)
        self.field(conn,'Port','port',0,2,8)
        self.field(conn,tr('Login SSH'),'user',0,4,18)
        ttk.Label(conn,text=tr('Logowanie')).grid(row=1,column=0,sticky='w',padx=4,pady=5)
        self.auth_list=ttk.Combobox(conn,textvariable=self.mode,values=[tr('Hasło'),tr('Klucz')],state='readonly',width=14)
        self.auth_list.grid(row=1,column=1,sticky='ew',padx=4)
        self.field(conn,tr('Hasło konta'),'password',1,2,18,True)
        self.field(conn,tr('Hasło sudo'),'sudo_password',1,4,18,True)
        self.field(conn,tr('Plik prywatny'),'key_path',2,0,26)
        self.button(conn,tr('Wybierz klucz…'),self.choose_key).grid(row=2,column=2,padx=4)
        self.field(conn,tr('Hasło klucza'),'passphrase',2,3,18,True)
        bar=ttk.Frame(conn);bar.grid(row=3,column=0,columnspan=6,sticky='w',pady=(8,0))
        self.button(bar,tr('Połącz i sprawdź'),self.connect,accent=True).pack(side='left')
        self.button(bar,tr('Rozłącz'),self.disconnect).pack(side='left',padx=8)
        ttk.Label(conn,text=tr('Hasła pozostają tylko w pamięci. Wymagane: Linux, OpenSSH, Python 3 i root/sudo; dla wyłączania haseł także systemd.'),foreground='#475569').grid(row=4,column=0,columnspan=6,sticky='w',pady=(8,0))
        gen=ttk.LabelFrame(outer,text=tr('2. Wygeneruj i zainstaluj nowy klucz RSA 3072'),padding=12);gen.pack(fill='x',pady=12)
        gen.columnconfigure(1,weight=1);gen.columnconfigure(3,weight=1)
        self.field(gen,tr('Hasło nowego klucza'),'new_pass',0,0,24,True)
        self.field(gen,tr('Powtórz hasło'),'confirm_pass',0,2,24,True)
        self.field(gen,tr('Folder kluczy'),'folder',1,0,24)
        self.button(gen,tr('Wybierz folder…'),self.choose_folder).grid(row=1,column=2,sticky='w',padx=4)
        self.field(gen,tr('Opis'),'comment',2,0,24)
        ttk.Checkbutton(gen,text=tr('Po teście nowego klucza wyłącz logowanie hasłem na serwerze'),variable=self.disable_pw).grid(row=2,column=2,columnspan=2,sticky='w',padx=4)
        gbar=ttk.Frame(gen);gbar.grid(row=3,column=0,columnspan=4,sticky='w',pady=(8,0))
        self.button(gbar,tr('Generuj → dodaj → przetestuj'),self.generate_install,accent=True).pack(side='left')
        self.button(gbar,tr('Zapisz sesję PuTTY'),self.save_putty).pack(side='left',padx=8)
        self.button(gbar,tr('Uruchom PuTTY'),self.open_putty).pack(side='left')
        ttk.Label(gen,text=tr('Klucz prywatny zostaje na komputerze. Na serwer trafia wyłącznie klucz publiczny.'),foreground='#475569').grid(row=4,column=0,columnspan=4,sticky='w',pady=(8,0))
        manage=ttk.LabelFrame(outer,text=tr('3. Klucze konta na serwerze'),padding=12);manage.pack(fill='both',expand=True)
        mbar=ttk.Frame(manage);mbar.pack(fill='x')
        ttk.Label(mbar,text=tr('Konto:')).pack(side='left')
        self.target=ttk.Combobox(mbar,textvariable=self.vars['target'],width=18);self.target.pack(side='left',padx=8)
        self.button(mbar,tr('Odśwież'),self.refresh).pack(side='left')
        self.button(mbar,tr('Dodaj klucz publiczny…'),self.add_public).pack(side='left',padx=8)
        self.button(mbar,tr('Usuń wybrany'),self.remove_key).pack(side='left')
        ttk.Label(manage,textvariable=self.count,foreground='#155e75').pack(anchor='w',pady=8)
        table=ttk.Frame(manage);table.pack(fill='both',expand=True)
        self.tree=ttk.Treeview(table,columns=('type','fingerprint','comment','options'),show='headings',height=5)
        for name,title,width in [('type',tr('Typ'),90),('fingerprint',tr('Identyfikator SHA256'),380),('comment',tr('Komentarz'),180),('options',tr('Ograniczenia wpisu'),170)]:
            self.tree.heading(name,text=title);self.tree.column(name,width=width,minwidth=60)
        scroll=ttk.Scrollbar(table,orient='vertical',command=self.tree.yview);self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left',fill='both',expand=True);scroll.pack(side='right',fill='y')
        self.log=tk.Text(outer,height=4,wrap='word',font=('Consolas',9),state='disabled',bg='#0f172a',fg='#e2e8f0',relief='flat',padx=10,pady=8)
        self.log.pack(fill='x',pady=(12,8))
        ttk.Label(outer,textvariable=self.status,foreground='#475569',wraplength=1040).pack(anchor='w')
        self.load_profile();self.after(80,self.drain)
        self.protocol('WM_DELETE_WINDOW',self.close_app)

    def field(self,parent,label,key,row,column,width=20,secret=False):
        ttk.Label(parent,text=label).grid(row=row,column=column,sticky='w',padx=4,pady=5)
        ttk.Entry(parent,textvariable=self.vars[key],width=width,show='●' if secret else '').grid(row=row,column=column+1,sticky='ew',padx=4,pady=5)

    def button(self,parent,text,command,accent=False):
        b=ttk.Button(parent,text=text,command=command,style='Accent.TButton' if accent else 'TButton');self.actions.append(b);return b

    def note(self,text):
        text=translate_message(text)
        self.log.configure(state='normal');self.log.insert('end',datetime.datetime.now().strftime('%H:%M:%S')+'  '+text+'\n');self.log.see('end');self.log.configure(state='disabled')

    def drain(self):
        try:
            while True:
                callback=self.events.get_nowait();callback()
        except queue.Empty: pass
        self.after(80,self.drain)

    def task(self,label,work,done=lambda result:None):
        if self.busy:return
        self.busy=True;self.status.set(label)
        for b in self.actions:b.configure(state='disabled')
        def finish(result=None,error=None):
            self.busy=False
            for b in self.actions:b.configure(state='normal')
            if error:
                self.status.set(tr('Operacja nie została ukończona.'));self.note(str(error));messagebox.showerror('SSH_Keys_Generator',str(error),parent=self)
            else:
                self.status.set(tr('Gotowe.'));done(result)
        def worker():
            try:
                result=work();self.events.put(lambda:finish(result=result))
            except Exception as e:
                self.events.put(lambda error=e:finish(error=error))
        threading.Thread(target=worker,daemon=True).start()

    def trust(self,host,kind,fp):
        ready=threading.Event();answer=[]
        def prompt():
            answer.append(messagebox.askyesno(tr('Sprawdź tożsamość serwera'),f"{tr('Pierwsze połączenie z ')}{host}\n\n{kind}\n{fp}{tr('\n\nPorównaj identyfikator z panelem dostawcy lub znanym połączeniem PuTTY.\nCzy ten klucz serwera jest prawidłowy?')}",parent=self));ready.set()
        self.events.put(prompt);ready.wait();return answer[0]

    def config(self):
        host=self.vars['host'].get().strip();user=self.vars['user'].get().strip()
        port=int(self.vars['port'].get())
        if not host or not user or not 1<=port<=65535:raise ValueError(tr('Podaj adres, login i port od 1 do 65535.'))
        if any(c.isspace() for c in host+user) or ',' in user:raise ValueError(tr('Nieprawidłowy adres lub login.'))
        return Connection(host,port,user,self.vars['password'].get(),self.vars['key_path'].get().strip() if self.mode.get()=='Klucz' else '',self.vars['passphrase'].get(),self.vars['sudo_password'].get())

    def connect(self):
        try:
            cfg=self.config()
            if self.mode.get()=='Klucz' and not cfg.key_path:raise ValueError(tr('Wybierz plik klucza prywatnego.'))
        except Exception as e:messagebox.showerror(tr('Dane połączenia'),str(e));return
        if self.server:self.server.close();self.server=None
        self.generated_key=None;self.generated_folder=None
        def work():
            s=Server(cfg,self.trust)
            try:return s,s.call('list'),s.call('users')
            except Exception:s.close();raise
        def done(result):
            self.server,state,users=result;self.target.configure(values=users['users']);self.vars['target'].set(cfg.user)
            self.render(state);self.note(f"{tr('Połączono: ')}{cfg.user}@{cfg.host}:{cfg.port}{tr('. Tożsamość serwera sprawdzona.')}")
        self.task(tr('Łączenie i odczyt konfiguracji…'),work,done)

    def disconnect(self):
        if self.server:self.server.close()
        self.server=None;self.state=None;self.generated_key=None
        for k in ['password','sudo_password','passphrase','new_pass','confirm_pass']:self.vars[k].set('')
        self.tree.delete(*self.tree.get_children());self.count.set(tr('Niepołączony.'));self.status.set(tr('Rozłączono. Hasła usunięto z formularza.'))

    def require(self):
        if not self.server:messagebox.showinfo(tr('Połączenie'),tr('Najpierw połącz się z serwerem.'));return False
        return True

    def render(self,state):
        self.state=state;self.tree.delete(*self.tree.get_children())
        for i,k in enumerate(state['keys']):
            self.tree.insert('', 'end',iid=str(i),values=(k['kind'],k['fingerprint'],k['comment'],k['options']))
        self.count.set(f"{tr('Konto: ')}{state['user']}{tr(' • wpisów kluczy: ')}{len(state['keys'])}{tr(' • plików: ')}{len(state['paths'])}{tr(' • hasło SSH: ')}{state['password']}{tr(' • klawiaturowe: ')}{state['keyboard']}")
        if state.get('backup'):self.note(tr('Kopia na serwerze: ')+state['backup'])
        if state.get('ca','none')!='none':self.note(tr('Serwer dopuszcza certyfikaty SSH (CA). Lista nie obejmuje dostępów przyznanych certyfikatami.'))

    def refresh(self):
        if not self.require():return
        user=self.vars['target'].get().strip()
        self.task(tr('Odczyt kluczy…'),lambda:self.server.call('list',user),self.render)

    def choose_key(self):
        p=filedialog.askopenfilename(title=tr('Klucz prywatny PPK (RSA) lub OpenSSH'),filetypes=[(tr('Klucze'),'*.ppk *.pem id_*'),(tr('Wszystkie'),'*.*')])
        if p:self.vars['key_path'].set(p);self.mode.set('Klucz')

    def choose_folder(self):
        p=filedialog.askdirectory()
        if p:self.vars['folder'].set(p)

    def generate_install(self):
        if not self.require():return
        password=self.vars['new_pass'].get();comment=self.vars['comment'].get().strip()
        if password!=self.vars['confirm_pass'].get():messagebox.showerror('Hasło',tr('Hasła nowego klucza nie są identyczne.'));return
        if len(password)<12:messagebox.showerror('Hasło',tr('Użyj hasła klucza o długości co najmniej 12 znaków.'));return
        if not comment or '\n' in comment or '\r' in comment:messagebox.showerror(tr('Opis'),tr('Podaj krótki, jednowierszowy opis klucza.'));return
        folder=Path(self.vars['folder'].get())/('key-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
        disable=self.disable_pw.get();s=self.server
        if disable and not messagebox.askyesno(tr('Wyłączenie haseł SSH'),tr('Po dodaniu klucza program przetestuje nowe połączenie, a następnie wyłączy hasła SSH na całym serwerze.\n\nZmiana nie dotyczy haseł poczty ani WWW. Inni użytkownicy SSH będą potrzebować kluczy.\n\nKontynuować?'),parent=self):return
        def work():
            key,public,path=generate(folder,password,comment)
            self.events.put(lambda:self.note(tr('Klucze zapisane lokalnie: ')+str(path)))
            state=s.call('list')
            state=s.call('add',public=public,revisions=state['revisions'])
            verified=s.test_key(key)
            verified.close()
            if disable:s.disable_passwords(key)
            # Keep the verified private key in memory for deletion protection / next operations.
            next_server=s.test_key(key)
            next_server.config.key_path=str(path/'id_rsa.ppk');next_server.config.passphrase=password
            state=next_server.call('list')
            return key,path,next_server,state
        def done(result):
            key,path,new_server,state=result;s.close();self.server=new_server;self.generated_key=key;self.generated_folder=path
            self.vars['key_path'].set(str(path/'id_rsa.ppk'));self.vars['passphrase'].set(password);self.mode.set('Klucz');self.vars['target'].set(new_server.config.user)
            self.render(state);self.note(tr('Nowe połączenie kluczem potwierdzone.')+(tr(' Hasła SSH wyłączone.') if disable else tr(' Ustawienia logowania hasłem pozostawione.')))
            self.vars['new_pass'].set('');self.vars['confirm_pass'].set('')
            messagebox.showinfo(tr('Klucz gotowy'),f"{tr('Pliki zapisano w:\n')}{path}{tr('\n\nDo PuTTY użyj id_rsa.ppk. Przechowuj bezpiecznie plik i jego hasło.\nMożesz teraz zapisać sesję PuTTY.')}",parent=self)
        self.task(tr('Generowanie, instalacja i test klucza…'),work,done)

    def add_public(self):
        if not self.require() or not self.state:return
        line=simpledialog.askstring(tr('Dodaj klucz'),tr('Wklej jeden klucz PUBLICZNY OpenSSH (np. ssh-ed25519 AAAA… opis).\nNie wklejaj klucza prywatnego.'),parent=self)
        if not line:return
        state=self.state
        self.task(tr('Dodawanie klucza i tworzenie kopii…'),lambda:self.server.call('add',state['user'],public=line,revisions=state['revisions']),self.render)

    def remove_key(self):
        if not self.require() or not self.state:return
        selected=self.tree.selection()
        if not selected:return
        state=self.state;k=state['keys'][int(selected[0])]
        if not messagebox.askyesno(tr('Usuń dostęp'),f"{tr('Konto: ')}{state['user']}\n{k['fingerprint']}\n{k['comment']}{tr('\n\nUsunąć ten wpis? Powstanie kopia pliku na serwerze.')}",parent=self):return
        self.task(tr('Usuwanie wybranego wpisu…'),lambda:self.server.call('remove',state['user'],file=k['file'],line=k['line'],revisions=state['revisions']),self.render)

    def export_with_keys(self):
        if self.busy or self.profiles is None:return
        if not self.profiles.items:
            messagebox.showinfo(tr('Eksport'),tr('Najpierw zapisz profile.'),parent=self);return
        password=simpledialog.askstring(tr('Hasło pakietu'),tr('Podaj nowe hasło pakietu (minimum 12 znaków).\nZalecana długa, unikalna fraza. Hasła nie można odzyskać.\nPakiet obejmie wszystkie zapisane profile i wskazane w nich klucze prywatne.'),show='●',parent=self)
        if password is None:return
        if len(password)<12 or len(password)>1024:
            messagebox.showerror('Hasło',tr('Hasło musi mieć od 12 do 1024 znaków.'),parent=self);return
        confirm=simpledialog.askstring(tr('Potwierdź hasło'),tr('Powtórz hasło pakietu:'),show='●',parent=self)
        if confirm is None:return
        if password!=confirm:
            messagebox.showerror('Hasło',tr('Podane hasła są różne.'),parent=self);return
        path=filedialog.asksaveasfilename(parent=self,title=tr('Zapisz zaszyfrowany pakiet profili i kluczy'),initialfile='SSH_Keys_Generator_Pakiet.sshkg',defaultextension='.sshkg',filetypes=[(tr('Zaszyfrowany pakiet'),'*.sshkg')])
        if not path:return
        self.task(tr('Szyfrowanie profili i kluczy…'),lambda:export_bundle(self.profiles,path,password),
                  lambda result:messagebox.showinfo(tr('Pakiet zapisany'),f"{tr('Profile: ')}{result[0]}{tr('. Pliki kluczy: ')}{result[1]}{tr('.\nPakiet jest zaszyfrowany. Zachowaj jego hasło oddzielnie.\nDotychczasowe hasła kluczy nadal obowiązują.')}",parent=self))

    def import_with_keys(self):
        if self.busy or self.profiles is None:return
        path=filedialog.askopenfilename(parent=self,title=tr('Otwórz zaszyfrowany pakiet'),filetypes=[(tr('Zaszyfrowany pakiet'),'*.sshkg')])
        if not path:return
        password=simpledialog.askstring(tr('Hasło pakietu'),tr('Podaj hasło zaszyfrowanego pakietu:'),show='●',parent=self)
        if password is None:return
        self.task(tr('Odszyfrowywanie i sprawdzanie pakietu…'),lambda:read_bundle(path,password),self.finish_bundle_import)

    def finish_bundle_import(self,bundle):
        incoming=bundle[0]
        conflicts=set(incoming)&set(self.profiles.items)
        overwrite=False
        if conflicts:
            choice=messagebox.askyesnocancel(tr('Powtarzające się nazwy'),f"{tr('Liczba istniejących nazw: ')}{len(conflicts)}{tr('.\nTak — zastąp profile.\nNie — pomiń duplikaty.\nAnuluj — nie importuj niczego.\nIstniejące pliki kluczy nie zostaną nadpisane.')}",parent=self)
            if choice is None:return
            overwrite=choice
        old_active=self.profiles.items.get(self.active_profile)
        def complete(result):
            self.update_profiles()
            if old_active!=self.profiles.items.get(self.active_profile):self.apply_profile(self.active_profile)
            messagebox.showinfo(tr('Import zakończony'),f"{tr('Zaimportowano: ')}{result[0]}{tr('. Pominięto: ')}{result[1]}{tr('.\nKlucze zapisano lokalnie, a ścieżki profili dostosowano.\nWybierz profil i połącz się. Dotychczasowe hasło klucza nadal obowiązuje.')}",parent=self)
        self.task(tr('Zapisywanie kluczy i profili…'),lambda:import_bundle(self.profiles,bundle,overwrite),complete)

    def export_profiles(self):
        if self.busy or self.profiles is None:return
        if not self.profiles.items:
            messagebox.showinfo(tr('Eksport'),tr('Najpierw zapisz co najmniej jeden profil.'),parent=self);return
        path=filedialog.asksaveasfilename(parent=self,title=tr('Eksportuj wszystkie zapisane profile'),initialfile='SSH_Keys_Generator_Profile.json',defaultextension='.json',filetypes=[(tr('Profile JSON'),'*.json')])
        if not path:return
        try:self.profiles.export_file(path)
        except (OSError,ValueError) as e:
            messagebox.showerror(tr('Eksport'),str(e),parent=self);return
        messagebox.showinfo(tr('Eksport zakończony'),f"{tr('Wyeksportowano ')}{len(self.profiles.items)}{tr(' profili.\nPlik zawiera adresy, loginy i ścieżki kluczy, ale nie zawiera haseł ani kluczy prywatnych.\nKlucze przenieś osobno bezpieczną metodą; na drugim komputerze popraw ich ścieżki.')}",parent=self)

    def import_profiles(self):
        if self.busy or self.profiles is None:return
        path=filedialog.askopenfilename(parent=self,title=tr('Importuj profile'),filetypes=[(tr('Profile JSON'),'*.json')])
        if not path:return
        try:
            incoming=read_export(path)
            conflicts=set(incoming)&set(self.profiles.items)
            overwrite=False
            if conflicts:
                choice=messagebox.askyesnocancel(tr('Powtarzające się nazwy'),f"{tr('Liczba profili o istniejących nazwach: ')}{len(conflicts)}{tr('.\nTak — zastąp istniejące profile.\nNie — pomiń powtarzające się nazwy.\nAnuluj — przerwij cały import.')}",parent=self)
                if choice is None:return
                overwrite=choice
            old_active=self.profiles.items.get(self.active_profile)
            count,skipped=self.profiles.merge(incoming,overwrite)
            self.update_profiles()
            if old_active != self.profiles.items.get(self.active_profile):
                self.apply_profile(self.active_profile)
            messagebox.showinfo(tr('Import zakończony'),f"{tr('Zaimportowano: ')}{count}{tr('. Pominięto: ')}{skipped}{tr('.\nWybierz profil z listy. Sprawdź ścieżkę klucza na tym komputerze przed połączeniem.\nImport nie nawiązuje połączenia z serwerem.')}",parent=self)
        except (OSError,ValueError) as e:messagebox.showerror(tr('Import'),str(e),parent=self)

    def update_profiles(self):
        self.profile_list.configure(values=sorted(self.profiles.items, key=str.casefold))

    def save_profile(self):
        if self.busy or self.profiles is None:return
        try:
            self.config()
            name=simpledialog.askstring(tr('Zapisz profil'),tr('Nazwa serwera / profilu:'),initialvalue=self.profile_name.get(),parent=self)
            if name is None:return
            name=name.strip()
            if name in self.profiles.items and not messagebox.askyesno(tr('Zastąpić profil?'),f"{tr('Zastąpić zapisany profil „')}{name}{tr('”?')}",parent=self):return
            data={k:self.vars[k].get() for k in FIELDS if k!='mode'}
            data['mode']=self.mode.get()
            self.profiles.save(name,data)
            self.update_profiles();self.profile_name.set(name);self.active_profile=name
            self.note(tr('Zapisano profil: ')+name+tr('. Bez haseł i zawartości kluczy.'))
        except (OSError,ValueError) as e:messagebox.showerror(tr('Profil'),str(e),parent=self)

    def apply_profile(self, name):
        self.disconnect()
        self.disable_pw.set(False)
        self.vars['target'].set('');self.target.configure(values=[])
        self.generated_folder=None
        data=self.profiles.items.get(name,{})
        for k in FIELDS:
            if k!='mode':self.vars[k].set(data.get(k,'22' if k=='port' else ''))
        self.mode.set(data.get('mode','Hasło'))
        self.active_profile=name;self.profile_name.set(name)

    def select_profile(self, event=None):
        if self.busy:
            self.profile_name.set(self.active_profile)
            return
        name=self.profile_name.get()
        if self.profiles is None or name not in self.profiles.items:return
        self.apply_profile(name)
        try:self.profiles.write(self.profiles.items,name)
        except OSError as e:messagebox.showerror(tr('Zapamiętanie profilu'),str(e),parent=self)
        self.note(tr('Wybrano profil: ')+name+tr('. Naciśnij „Połącz i sprawdź”.'))

    def new_profile(self):
        if self.busy or self.profiles is None:return
        self.apply_profile('')

    def delete_profile(self):
        if self.busy or self.profiles is None:return
        name=self.profile_name.get()
        if name not in self.profiles.items:return
        if not messagebox.askyesno(tr('Usuń profil'),f"{tr('Usunąć profil „')}{name}{tr('” z tego komputera? Klucze i dane na serwerze pozostaną bez zmian.')}",parent=self):return
        try:self.profiles.delete(name)
        except OSError as e:
            messagebox.showerror(tr('Profil'),str(e),parent=self);return
        self.apply_profile('');self.update_profiles()

    def load_profile(self):
        try:
            self.profiles=Profiles(APP_DATA)
            self.update_profiles()
            if self.profiles.selected:self.apply_profile(self.profiles.selected)
        except (OSError,ValueError,TypeError) as e:
            self.note(tr('Nie można odczytać profili: ')+str(e)+tr('. Plik nie został nadpisany; zapisywanie profili jest wyłączone.'))

    def change_language(self,lang):
        if self.busy or lang==i18n.LANGUAGE:return
        old_catalog=i18n.CATALOGS[i18n.LANGUAGE]
        reverse={translated:source for source,translated in old_catalog.items()}
        mode=self.mode.get()
        i18n.set_language(lang)
        def visit(widget):
            try:
                text=widget.cget('text')
                if text:widget.configure(text=tr(reverse.get(str(text),str(text))))
            except tk.TclError:pass
            for child in widget.winfo_children():visit(child)
        visit(self)
        self.auth_list.configure(values=[tr('Hasło'),tr('Klucz')]);self.mode.set(mode)
        for name in self.tree['columns']:
            text=self.tree.heading(name,'text');self.tree.heading(name,text=tr(reverse.get(text,text)))
        if self.state:self.render(self.state)
        else:
            self.status.set(tr('Niepołączony.'))
            self.count.set(tr('Połącz się, aby odczytać klucze wybranego konta.'))
        if self.help_window is not None and self.help_window.winfo_exists():
            self.help_window.destroy();self.show_help()
        if self.about_window is not None and self.about_window.winfo_exists():
            self.about_window.destroy();self.show_about()

    def check_updates(self):
        if self.busy:return
        self.task(tr('Sprawdzanie wydań na GitHubie…'),check_latest,self.offer_update)

    def offer_update(self,release):
        current=version_tuple(VERSION);latest=version_tuple(release.version)
        if latest<current:
            messagebox.showinfo(tr('Aktualizacje'),tr('Twoja wersja jest nowsza niż ostatnie stabilne wydanie na GitHubie.'),parent=self);return
        state=tr('Dostępna jest nowa wersja.') if latest>current else tr('Masz aktualną wersję. Możesz pobrać jej instalator ponownie.')
        prompt=state+'\n\n'+tr('Zainstalowana: ')+VERSION+'\n'+tr('Dostępna: ')+release.version+'\n\n'+tr('Pobrać instalator? Program sprawdzi sumę SHA256. Instalacja nie uruchomi się automatycznie.')
        if not messagebox.askyesno(tr('Aktualizacje'),prompt,parent=self):return
        path=filedialog.asksaveasfilename(parent=self,title=tr('Zapisz instalator'),initialfile='SSH_Keys_Generator_Setup_'+release.version+'.exe',defaultextension='.exe',filetypes=[(tr('Instalator Windows'),'*.exe')])
        if not path:return
        self.task(tr('Pobieranie i weryfikacja instalatora…'),lambda:download_installer(release,path),
                  lambda saved:messagebox.showinfo(tr('Instalator pobrany'),tr('Suma SHA256 jest poprawna. Zapisano plik:')+'\n'+str(saved)+'\n\n'+tr('Po zakończeniu pracy zamknij program i uruchom pobrany instalator. Twoje profile i klucze zostaną zachowane.'),parent=self))

    def show_about(self):
        if self.about_window is not None and self.about_window.winfo_exists():
            self.about_window.lift();return
        window=tk.Toplevel(self);self.about_window=window
        window.title('About — SSH_Keys_Generator');window.geometry('640x370')
        body=ttk.Frame(window,padding=24);body.pack(fill='both',expand=True)
        ttk.Label(body,text='SSH_Keys_Generator '+VERSION,font=('Segoe UI',18,'bold')).pack(anchor='w',pady=(0,12))
        description=('A utility that makes it easier to set up SSH key authentication for logging in to a remote server.' if i18n.LANGUAGE=='en' else 'Program narzędziowy ułatwiający konfigurację logowania do zdalnego serwera za pomocą klucza SSH.')
        ttk.Label(body,text=description,wraplength=580).pack(anchor='w',pady=(0,12))
        ttk.Label(body,text=COPYRIGHT).pack(anchor='w')
        ttk.Label(body,text=CONTACT).pack(anchor='w',pady=(4,12))
        link=ttk.Label(body,text=REPOSITORY_URL,foreground='#0369a1',cursor='hand2');link.pack(anchor='w')
        link.bind('<Button-1>',lambda event:webbrowser.open(REPOSITORY_URL))
        ttk.Label(body,text=LICENSE_NAME).pack(anchor='w',pady=(12,4))
        ttk.Button(body,text='License' if i18n.LANGUAGE=='en' else 'Licencja',command=self.show_license).pack(anchor='w')
        ttk.Button(body,text=tr('Zamknij'),command=window.destroy).pack(anchor='e')

    def show_license(self):
        window=tk.Toplevel(self);window.title(LICENSE_NAME);window.geometry('850x650')
        body=ttk.Frame(window,padding=12);body.pack(fill='both',expand=True)
        text=tk.Text(body,wrap='word',font=('Consolas',10))
        scroll=ttk.Scrollbar(body,command=text.yview);text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');text.pack(fill='both',expand=True)
        text.insert('1.0',(RESOURCE_DIR/'LICENSE').read_text('utf-8'));text.configure(state='disabled')

    def show_help(self):
        if self.help_window is not None and self.help_window.winfo_exists():
            self.help_window.lift();return
        try:
            directory=Path(getattr(sys,'_MEIPASS',Path(__file__).parent))
            contents=(directory/('GUIDE_EN.txt' if i18n.LANGUAGE=='en' else 'INSTRUKCJA.txt')).read_text('utf-8')
        except OSError as e:
            messagebox.showerror(tr('Instrukcja'),str(e),parent=self);return
        window=tk.Toplevel(self);self.help_window=window
        window.title(tr('Instrukcja')+' — SSH_Keys_Generator '+VERSION);window.geometry('850x650')
        body=ttk.Frame(window,padding=12);body.pack(fill='both',expand=True)
        text=tk.Text(body,wrap='word',font=('Segoe UI',11),padx=12,pady=12)
        scroll=ttk.Scrollbar(body,command=text.yview);text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');text.pack(fill='both',expand=True)
        text.insert('1.0',contents);text.configure(state='disabled')
        ttk.Button(window,text=tr('Zamknij'),command=window.destroy).pack(pady=(0,10))

    def key_for_putty(self):
        if not self.require():return None
        p=self.server.config.key_path
        if not p or Path(p).suffix.lower()!='.ppk':
            messagebox.showinfo('PuTTY',tr('Wygeneruj klucz w programie lub połącz się przy użyciu pliku PPK.'));return None
        return p

    def save_putty(self):
        p=self.key_for_putty()
        if not p:return
        import winreg
        from urllib.parse import quote
        cfg=self.server.config
        name='SSH_Keys_Generator - '+cfg.user+'@'+cfg.host+'-'+str(cfg.port)
        reg_path='Software\\SimonTatham\\PuTTY\\Sessions\\'+quote(name,safe='-_.@')
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,reg_path):exists=True
        except FileNotFoundError:exists=False
        if exists and not messagebox.askyesno(tr('Sesja PuTTY'),tr('Zastąpić ustawienia sesji ')+name+'?',parent=self):return
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,reg_path) as reg:
            for k,v in {'HostName':cfg.host,'UserName':cfg.user,'Protocol':'ssh','PublicKeyFile':p}.items():winreg.SetValueEx(reg,k,0,winreg.REG_SZ,v)
            winreg.SetValueEx(reg,'PortNumber',0,winreg.REG_DWORD,cfg.port)
        self.note(tr('Zapisano sesję PuTTY: ')+name)

    def open_putty(self):
        p=self.key_for_putty()
        if not p:return
        candidates=[Path(os.environ.get('ProgramFiles','C:/Program Files'))/'PuTTY/putty.exe',Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'PuTTY/putty.exe']
        exe=next((str(p) for p in candidates if p.exists()),None)
        if not exe:exe=filedialog.askopenfilename(title=tr('Wskaż putty.exe'),filetypes=[('PuTTY','putty.exe')])
        if not exe:return
        c=self.server.config
        subprocess.Popen([exe,'-ssh','-P',str(c.port),'-l',c.user,'-i',p,'-hostkey',fingerprint(self.server.hostkey.asbytes()),c.host])

    def close_app(self):
        if self.busy:
            messagebox.showinfo(tr('Operacja trwa'),tr('Poczekaj na zakończenie operacji. Przy wyłączaniu haseł działa niezależny mechanizm powrotu na serwerze.'));return
        if self.server:self.server.close()
        self.destroy()


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--lang',choices=['en','pl'],default='en')
    i18n.set_language(parser.parse_args().lang)
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:pass
    App().mainloop()
