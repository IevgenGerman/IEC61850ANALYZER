# -*- coding: utf-8 -*-
"""
updater.py - check on GitHub whether a newer version exists (only the Python standard library:
urllib + json, nothing to add to requirements.txt).

The newest release of the repository (GitHub Releases, made by .github/workflows/build.yml when
a tag like v0.2.1 is pushed) is read from
    https://api.github.com/repos/<owner>/<repo>/releases/latest
(if the repository has no release yet: the tags). Its tag is compared with VERSION of the program.
The check runs in a background thread with a short timeout: no network / proxy / private
repository -> nothing is shown, the program works as usual.
"""
import json
import re
import threading
import urllib.request

TIMEOUT = 5


def parse_version(text):
    """'v 0.2.0' / 'v0.2.1' / '0.10.3-beta' -> (0, 2, 0) ... (None if no number)"""
    m = re.search(r"(\d+(?:\.\d+)*)", text or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "IEC61850ANALYZER-update-check"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def latest(repo):
    """-> dict(tag, version tuple, url (page), exe (download url or None), notes) or None"""
    try:
        d = _get("https://api.github.com/repos/%s/releases/latest" % repo)
        assets = d.get("assets", [])                       # zip of the program folder (v0.6.4+) or exe
        exe = next((a.get("browser_download_url") for a in assets
                    if str(a.get("name", "")).lower().endswith(".zip")), None) or \
            next((a.get("browser_download_url") for a in assets
                  if str(a.get("name", "")).lower().endswith(".exe")), None)
        return dict(tag=d.get("tag_name", ""), version=parse_version(d.get("tag_name")),
                    url=d.get("html_url") or "https://github.com/%s/releases" % repo, exe=exe,
                    notes=(d.get("body") or "").strip())
    except Exception:
        pass
    try:                                                   # no release yet -> newest tag
        tags = _get("https://api.github.com/repos/%s/tags" % repo)
        best = max((t for t in tags if parse_version(t.get("name"))), key=lambda t: parse_version(t["name"]))
        return dict(tag=best["name"], version=parse_version(best["name"]),
                    url="https://github.com/%s/releases" % repo, exe=None, notes="")
    except Exception:
        return None


def check(repo, current, callback):
    """background check; callback(info) only when a newer version exists (info as latest())"""
    if not repo:
        return

    def run():
        info = latest(repo)
        cur = parse_version(current)
        if info and info["version"] and cur and info["version"] > cur:
            callback(info)
    threading.Thread(target=run, daemon=True).start()


def check_now(repo, current):
    """synchronous check for the button in the About window -> (state, info):
    'newer' / 'current' / 'error'"""
    info = latest(repo) if repo else None
    if not info or not info["version"]:
        return "error", info
    cur = parse_version(current)
    return ("newer" if cur and info["version"] > cur else "current"), info
