"""Self-update of the packaged exe from the latest GitHub release.

At start the exe asks the GitHub API for the latest release of REPO. If its tag is
newer than the running version and it has a sds_meter.exe asset, a dialog offers
the update; on Yes the new exe is downloaded next to the running one, the running
exe is renamed to .old (Windows allows renaming a running exe, not overwriting it),
the new one takes its name, and the caller restarts into it. The .old file is
deleted on the next start. Running from source (python -m sds_meter) never updates.
"""
import json, os, sys, threading, urllib.request

REPO = "nathanmarble/sdsmeter"                      # GitHub "owner/name" the releases are published on
ASSET = "sds_meter.exe"
TIMEOUT = 15


def exe_path():
    """The packaged exe (for Nuitka onefile, not the temp folder it unpacks to), or None from source."""
    main = sys.modules.get("__main__")
    compiled = getattr(main, "__compiled__", None)
    if compiled is None:
        return None
    argv0 = getattr(compiled, "original_argv0", None) or sys.argv[0]
    path = os.path.abspath(argv0)
    if not path.lower().endswith(".exe"):
        path += ".exe"
    return path if os.path.isfile(path) else None


def parse_version(text):
    """'v1.2.10' -> (1, 2, 10); anything unparsable -> ()."""
    parts = []
    for p in text.strip().lstrip("vV").split("."):
        digits = "".join(c for c in p if c.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _get(url, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"User-Agent": "SDS-Meter-updater", "Accept": accept})
    return urllib.request.urlopen(req, timeout=TIMEOUT)


def latest_release():
    """(version tag, download url, size) of the newest release's exe, or None."""
    with _get(f"https://api.github.com/repos/{REPO}/releases/latest") as r:
        rel = json.load(r)
    for a in rel.get("assets", []):
        if a.get("name", "").lower() == ASSET:
            return rel.get("tag_name", ""), a["browser_download_url"], a.get("size", 0)
    return None


def cleanup():
    """Delete the exe left over from the last update."""
    exe = exe_path()
    if exe:
        try:
            os.remove(exe + ".old")
        except OSError:
            pass


def _ask(text, flags=0x24):                       # MB_YESNO | MB_ICONQUESTION
    import ctypes
    flags |= 0x40000 | 0x10000                    # MB_TOPMOST | MB_SETFOREGROUND: show above the game
    return ctypes.windll.user32.MessageBoxW(None, text, "SDS Meter update", flags)


def _install(exe, url, size):
    """Download to exe.new, check it, swap it in. Raises on any failure, leaving the old exe."""
    new, old = exe + ".new", exe + ".old"
    with _get(url, accept="application/octet-stream") as r, open(new, "wb") as f:
        while chunk := r.read(1 << 16):
            f.write(chunk)
    with open(new, "rb") as f:
        head = f.read(2)
    if head != b"MZ" or (size and os.path.getsize(new) != size):
        os.remove(new)
        raise OSError("downloaded file is incomplete or not an exe")
    try:
        os.remove(old)
    except OSError:
        pass
    os.rename(exe, old)
    try:
        os.rename(new, exe)
    except OSError:
        os.rename(old, exe)                       # put the running version back
        raise


def check(current, on_installed, log=print):
    """Look for a newer release in the background; after the user accepts and it is
    installed, call on_installed(exe path) (from the worker thread)."""
    exe = exe_path()
    if not exe or REPO == "OWNER/REPO":
        return

    def work():
        accepted = False
        try:
            found = latest_release()
            if not found:
                return
            tag, url, size = found
            if parse_version(tag) <= parse_version(current):
                return
            log(f"update: {current} -> {tag} available")
            if _ask(f"SDS Meter {tag.lstrip('vV')} is available (you have {current}).\n\n"
                    "Download and install it now? The meter restarts by itself.") != 6:   # IDYES
                return
            accepted = True
            _install(exe, url, size)
            log(f"update: installed {tag}")
            on_installed(exe)
        except Exception as e:                    # offline, rate limit, no write access...
            log(f"update: failed: {e!r}")
            if accepted:                          # only bother the user if they asked for it
                _ask(f"The update could not be installed:\n{e}\n\nGet it from "
                     f"https://github.com/{REPO}/releases instead.", 0x30)   # MB_OK | MB_ICONWARNING
    threading.Thread(target=work, daemon=True, name="updater").start()
