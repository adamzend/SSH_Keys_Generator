# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""Public GitHub release checks and checksum-verified installer downloads."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from version import VERSION, REPOSITORY_URL

API_URL = 'https://api.github.com/repos/adamzend/SSH_Keys_Generator/releases/latest'
INSTALLER = 'SSH_Keys_Generator_Setup.exe'
MAX_INSTALLER = 200 * 1024 * 1024
ALLOWED_HOSTS = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com',
                 'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'v?(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})', value):
        raise ValueError('Nieobsługiwany numer wersji wydania.')
    return tuple(map(int, value.removeprefix('v').split('.')))


def validate_url(url):
    try:
        parts = urlsplit(url)
        valid = (parts.scheme == 'https' and parts.hostname in ALLOWED_HOSTS
                 and parts.port in (None, 443) and not parts.username and not parts.password)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError('Odrzucono niebezpieczny adres pobierania.')
    return url


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url):
    validate_url(url)
    request = Request(url, headers={
        'User-Agent': 'SSH_Keys_Generator/' + VERSION,
        'Accept': 'application/vnd.github+json' if url == API_URL else 'application/octet-stream'})
    try:
        return build_opener(SafeRedirect()).open(request, timeout=20)
    except HTTPError as error:
        if error.code in (403, 429):
            raise ValueError('GitHub ograniczył liczbę zapytań. Spróbuj ponownie później.') from None
        if error.code == 404:
            raise ValueError('Nie znaleziono opublikowanego wydania lub instalatora.') from None
        raise ValueError('GitHub zwrócił błąd pobierania. Spróbuj ponownie później.') from None
    except (URLError, TimeoutError, OSError):
        raise ValueError('Nie można połączyć się z GitHubem. Sprawdź internet i spróbuj ponownie.') from None


@dataclass(frozen=True)
class Release:
    tag: str
    version: str
    url: str
    size: int
    sha256: str


def check_latest():
    with open_url(API_URL) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('Odpowiedź GitHuba jest zbyt duża.')
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError('Nieprawidłowa odpowiedź GitHuba.') from None
    if not isinstance(data, dict) or data.get('draft') is not False or data.get('prerelease') is not False:
        raise ValueError('Wydanie nie jest stabilną, publiczną wersją.')
    tag = data.get('tag_name')
    version_tuple(tag)
    assets = data.get('assets')
    if not isinstance(assets, list):
        raise ValueError('Brak instalatora w wydaniu.')
    matches = [a for a in assets if isinstance(a, dict) and a.get('name') == INSTALLER and a.get('state') == 'uploaded']
    if len(matches) != 1:
        raise ValueError('Brak instalatora w wydaniu.')
    asset = matches[0]
    url = asset.get('browser_download_url')
    if url != REPOSITORY_URL + '/releases/download/' + tag + '/' + INSTALLER:
        raise ValueError('Instalator nie pochodzi z oczekiwanego repozytorium.')
    size, digest = asset.get('size'), asset.get('digest')
    if type(size) is not int or not 0 < size <= MAX_INSTALLER:
        raise ValueError('Nieprawidłowy rozmiar instalatora.')
    if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', digest):
        raise ValueError('GitHub nie udostępnił poprawnej sumy SHA256 instalatora.')
    return Release(tag, tag.removeprefix('v'), url, size, digest[7:].lower())


def download_installer(release, destination):
    version_tuple(release.tag)
    if release.url != REPOSITORY_URL + '/releases/download/' + release.tag + '/' + INSTALLER:
        raise ValueError('Instalator nie pochodzi z oczekiwanego repozytorium.')
    if type(release.size) is not int or not 0 < release.size <= MAX_INSTALLER or not re.fullmatch(r'[0-9a-f]{64}', release.sha256):
        raise ValueError('Nieprawidłowe dane instalatora.')
    target = Path(destination).resolve()
    if target.suffix.lower() != '.exe' or target == Path(sys.executable).resolve():
        raise ValueError('Wybierz osobny plik instalatora z rozszerzeniem .exe.')
    temporary = None
    digest, count, deadline = hashlib.sha256(), 0, time.monotonic() + 300
    try:
        with open_url(release.url) as response:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.sshkg-download-', suffix='.part', delete=False) as stream:
                temporary = Path(stream.name)
                read = getattr(response, 'read1', response.read)
                while True:
                    if time.monotonic() > deadline:
                        raise ValueError('Upłynął czas pobierania instalatora.')
                    block = read(128 * 1024)
                    if not block:
                        break
                    count += len(block)
                    if count > release.size:
                        raise ValueError('Rozmiar pobranego instalatora jest niezgodny.')
                    digest.update(block)
                    stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
        if count != release.size or digest.hexdigest() != release.sha256:
            raise ValueError('Weryfikacja instalatora nie powiodła się. Plik nie został zapisany.')
        os.replace(temporary, target)
        return target
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
