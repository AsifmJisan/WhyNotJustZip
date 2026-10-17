#!/usr/bin/env python3
"""Project Resurrection Generator — standalone offline, password-protected project snapshots.

Python 3.9+; standard library only. Generates a self-restoring .py or .ps1 script.
The generated Python restorer also uses only the Python standard library.
"""
from __future__ import annotations
import base64, fnmatch, getpass, hashlib, hmac, json, os, secrets, shutil, stat, struct, sys, tempfile, time, zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

APP_NAME = "Project Resurrection"
FORMAT_VERSION = 2
KDF_ITERATIONS = 600_000
MAGIC = b"PRJRX2\0\0"  # exactly 8 bytes
HEADER_LEN = 8 + 4 + 16 + 16
TAG_LEN = 32
DATA_BEGIN = "#--RESURRECTION-DATA-BEGIN--"
DATA_END = "#--RESURRECTION-DATA-END--"

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", ".bzr", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".nox", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", ".cache",
    "cache", "build", "out", "coverage", ".gradle", ".idea", ".vscode-test", "target",
    "bower_components", "packages", ".next", ".nuxt", ".turbo", ".parcel-cache",
}
IGNORE_FILE_RE = lambda name: name.startswith(".") and name.endswith("ignore")
MANIFEST_NAME = ".resurrection-manifest.json"

AES_SOURCE = r'''# Self-contained table-based AES-256 implementation (FIPS 197), CBC + encrypt-then-MAC.
# This uses standard AES-256 primitives; keys are derived separately with PBKDF2-HMAC-SHA256.
def _aes_gf_mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1: out ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return out

def _aes_gf_pow(a, n):
    out = 1
    while n:
        if n & 1: out = _aes_gf_mul(out, a)
        a = _aes_gf_mul(a, a); n >>= 1
    return out

def _aes_rot8(x, n): return ((x << n) | (x >> (8 - n))) & 0xff

def _aes_make_sboxes():
    s = []
    for x in range(256):
        y = 0 if x == 0 else _aes_gf_pow(x, 254)
        s.append((y ^ _aes_rot8(y, 1) ^ _aes_rot8(y, 2) ^ _aes_rot8(y, 3) ^ _aes_rot8(y, 4) ^ 0x63) & 0xff)
    inv = [0] * 256
    for i, v in enumerate(s): inv[v] = i
    return tuple(s), tuple(inv)

_AES_S, _AES_IS = _aes_make_sboxes()

def _aes_make_table(vals, coeffs):
    table = []
    for x in vals:
        b = [_aes_gf_mul(x, c) for c in coeffs]
        table.append((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3])
    return tuple(table)

_AES_TE0 = _aes_make_table(_AES_S, (2, 1, 1, 3))
_AES_TE1 = _aes_make_table(_AES_S, (3, 2, 1, 1))
_AES_TE2 = _aes_make_table(_AES_S, (1, 3, 2, 1))
_AES_TE3 = _aes_make_table(_AES_S, (1, 1, 3, 2))
_AES_TD0 = _aes_make_table(_AES_IS, (14, 9, 13, 11))
_AES_TD1 = _aes_make_table(_AES_IS, (11, 14, 9, 13))
_AES_TD2 = _aes_make_table(_AES_IS, (13, 11, 14, 9))
_AES_TD3 = _aes_make_table(_AES_IS, (9, 13, 11, 14))

def _aes_sub_word(w):
    return (_AES_S[(w >> 24) & 255] << 24) | (_AES_S[(w >> 16) & 255] << 16) | (_AES_S[(w >> 8) & 255] << 8) | _AES_S[w & 255]

def _aes_inv_mix_word(w):
    a = [(w >> 24) & 255, (w >> 16) & 255, (w >> 8) & 255, w & 255]
    b = (_aes_gf_mul(a[0],14)^_aes_gf_mul(a[1],11)^_aes_gf_mul(a[2],13)^_aes_gf_mul(a[3],9),
         _aes_gf_mul(a[0],9)^_aes_gf_mul(a[1],14)^_aes_gf_mul(a[2],11)^_aes_gf_mul(a[3],13),
         _aes_gf_mul(a[0],13)^_aes_gf_mul(a[1],9)^_aes_gf_mul(a[2],14)^_aes_gf_mul(a[3],11),
         _aes_gf_mul(a[0],11)^_aes_gf_mul(a[1],13)^_aes_gf_mul(a[2],9)^_aes_gf_mul(a[3],14))
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]

def _aes_expand_key(key):
    if len(key) != 32: raise ValueError('AES-256 requires a 32-byte key')
    enc = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = enc[i-1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xffffffff
            t = _aes_sub_word(t) ^ (rcon << 24)
            rcon = _aes_gf_mul(rcon, 2)
        elif i % 8 == 4:
            t = _aes_sub_word(t)
        enc.append(enc[i-8] ^ t)
    dec = []
    for rnd in range(15):
        original_round = 14 - rnd
        for col in range(4):
            word = enc[original_round * 4 + col]
            if rnd not in (0, 14): word = _aes_inv_mix_word(word)
            dec.append(word)
    return enc, dec

def _aes_encrypt_block(block, round_keys):
    w = round_keys[0]
    s0 = int.from_bytes(block[0:4], 'big') ^ w[0]
    s1 = int.from_bytes(block[4:8], 'big') ^ w[1]
    s2 = int.from_bytes(block[8:12], 'big') ^ w[2]
    s3 = int.from_bytes(block[12:16], 'big') ^ w[3]
    for rnd in range(1, 14):
        off = rnd * 4
        t0 = _AES_TE0[(s0>>24)&255] ^ _AES_TE1[(s1>>16)&255] ^ _AES_TE2[(s2>>8)&255] ^ _AES_TE3[s3&255] ^ w[off]
        t1 = _AES_TE0[(s1>>24)&255] ^ _AES_TE1[(s2>>16)&255] ^ _AES_TE2[(s3>>8)&255] ^ _AES_TE3[s0&255] ^ w[off+1]
        t2 = _AES_TE0[(s2>>24)&255] ^ _AES_TE1[(s3>>16)&255] ^ _AES_TE2[(s0>>8)&255] ^ _AES_TE3[s1&255] ^ w[off+2]
        t3 = _AES_TE0[(s3>>24)&255] ^ _AES_TE1[(s0>>16)&255] ^ _AES_TE2[(s1>>8)&255] ^ _AES_TE3[s2&255] ^ w[off+3]
        s0,s1,s2,s3 = t0,t1,t2,t3
    off = 56
    o0 = (_AES_S[(s0>>24)&255]<<24)|(_AES_S[(s1>>16)&255]<<16)|(_AES_S[(s2>>8)&255]<<8)|_AES_S[s3&255]
    o1 = (_AES_S[(s1>>24)&255]<<24)|(_AES_S[(s2>>16)&255]<<16)|(_AES_S[(s3>>8)&255]<<8)|_AES_S[s0&255]
    o2 = (_AES_S[(s2>>24)&255]<<24)|(_AES_S[(s3>>16)&255]<<16)|(_AES_S[(s0>>8)&255]<<8)|_AES_S[s1&255]
    o3 = (_AES_S[(s3>>24)&255]<<24)|(_AES_S[(s0>>16)&255]<<16)|(_AES_S[(s1>>8)&255]<<8)|_AES_S[s2&255]
    return b''.join(((o ^ w[off+i]) & 0xffffffff).to_bytes(4, 'big') for i,o in enumerate((o0,o1,o2,o3)))

def _aes_decrypt_block(block, round_keys):
    w = round_keys[1]
    s0 = int.from_bytes(block[0:4], 'big') ^ w[0]
    s1 = int.from_bytes(block[4:8], 'big') ^ w[1]
    s2 = int.from_bytes(block[8:12], 'big') ^ w[2]
    s3 = int.from_bytes(block[12:16], 'big') ^ w[3]
    for rnd in range(1, 14):
        off = rnd * 4
        t0 = _AES_TD0[(s0>>24)&255] ^ _AES_TD1[(s3>>16)&255] ^ _AES_TD2[(s2>>8)&255] ^ _AES_TD3[s1&255] ^ w[off]
        t1 = _AES_TD0[(s1>>24)&255] ^ _AES_TD1[(s0>>16)&255] ^ _AES_TD2[(s3>>8)&255] ^ _AES_TD3[s2&255] ^ w[off+1]
        t2 = _AES_TD0[(s2>>24)&255] ^ _AES_TD1[(s1>>16)&255] ^ _AES_TD2[(s0>>8)&255] ^ _AES_TD3[s3&255] ^ w[off+2]
        t3 = _AES_TD0[(s3>>24)&255] ^ _AES_TD1[(s2>>16)&255] ^ _AES_TD2[(s1>>8)&255] ^ _AES_TD3[s0&255] ^ w[off+3]
        s0,s1,s2,s3 = t0,t1,t2,t3
    off = 56
    o0 = (_AES_IS[(s0>>24)&255]<<24)|(_AES_IS[(s3>>16)&255]<<16)|(_AES_IS[(s2>>8)&255]<<8)|_AES_IS[s1&255]
    o1 = (_AES_IS[(s1>>24)&255]<<24)|(_AES_IS[(s0>>16)&255]<<16)|(_AES_IS[(s3>>8)&255]<<8)|_AES_IS[s2&255]
    o2 = (_AES_IS[(s2>>24)&255]<<24)|(_AES_IS[(s1>>16)&255]<<16)|(_AES_IS[(s0>>8)&255]<<8)|_AES_IS[s3&255]
    o3 = (_AES_IS[(s3>>24)&255]<<24)|(_AES_IS[(s2>>16)&255]<<16)|(_AES_IS[(s1>>8)&255]<<8)|_AES_IS[s0&255]
    return b''.join(((o ^ w[off+i]) & 0xffffffff).to_bytes(4, 'big') for i,o in enumerate((o0,o1,o2,o3)))

def _aes_cbc_encrypt(data, key, iv):
    keys = _aes_expand_key(key); prev = iv; out = bytearray()
    pad = 16 - (len(data) % 16); data += bytes([pad]) * pad
    for pos in range(0, len(data), 16):
        block = bytes(a ^ b for a,b in zip(data[pos:pos+16], prev))
        prev = _aes_encrypt_block(block, keys); out.extend(prev)
    return bytes(out)

def _aes_cbc_decrypt(data, key, iv):
    if not data or len(data) % 16: raise ValueError('Invalid AES-CBC ciphertext length')
    keys = _aes_expand_key(key); prev = iv; out = bytearray()
    for pos in range(0, len(data), 16):
        block = data[pos:pos+16]; plain = _aes_decrypt_block(block, keys)
        out.extend(a ^ b for a,b in zip(plain, prev)); prev = block
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad: raise ValueError('Invalid encrypted payload/password')
    return bytes(out[:-pad])
'''
# Install the same tested, self-contained AES implementation for the generator itself.
exec(AES_SOURCE, globals())


def derive_keys(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> tuple[bytes, bytes]:
    raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)
    return raw[:32], raw[32:]


def encrypt_file(plain_path: Path, envelope_path: Path, password: str) -> tuple[int, int]:
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(16)
    header = MAGIC + struct.pack(">I", KDF_ITERATIONS) + salt + iv
    enc_key, mac_key = derive_keys(password, salt)
    mac = hmac.new(mac_key, header, hashlib.sha256)
    total_cipher = 0
    words = _aes_expand_key(enc_key); prev = iv; pending = b""
    with plain_path.open("rb") as src, envelope_path.open("wb") as dst:
        dst.write(header)
        def emit(buf: bytes):
            nonlocal prev, total_cipher
            out = bytearray()
            for p in range(0, len(buf), 16):
                block = bytes(a ^ b for a,b in zip(buf[p:p+16], prev))
                prev = _aes_encrypt_block(block, words); out.extend(prev)
            data = bytes(out); dst.write(data); mac.update(data); total_cipher += len(data)
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk: break
            pending += chunk
            usable = (len(pending) // 16) * 16
            if usable:
                emit(pending[:usable]); pending = pending[usable:]
        pad = 16 - len(pending)
        emit(pending + bytes([pad]) * pad)
        tag = mac.digest(); dst.write(tag)
    return envelope_path.stat().st_size, total_cipher


def _is_ignored_rule_filename(name: str) -> bool:
    return IGNORE_FILE_RE(name)


def _safe_decode(path: Path) -> str:
    try: return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _glob_match_path(pattern: str, path: str, case_sensitive: bool = True) -> bool:
    """Match Git-style glob where * and ? do not cross slash, but ** can."""
    import re
    if not case_sensitive:
        pattern, path = pattern.casefold(), path.casefold()
    regex = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                i += 2
                if i < len(pattern) and pattern[i] == "/":
                    regex.append("(?:.*/)?"); i += 1
                else:
                    regex.append(".*")
                continue
            regex.append("[^/]*")
        elif ch == "?":
            regex.append("[^/]")
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end < 0:
                regex.append(r"\[")
            else:
                cls = pattern[i + 1:end]
                if cls.startswith("!"): cls = "^" + cls[1:]
                regex.append("[" + cls + "]")
                i = end
        else:
            regex.append(re.escape(ch))
        i += 1
    return re.fullmatch("".join(regex), path) is not None


def _rule_match_git(rule: dict, relpath: str, is_dir: bool) -> bool:
    pat = rule["pattern"]
    base = rule["base"]
    if base:
        if relpath == base: local = ""
        elif relpath.startswith(base + "/"): local = relpath[len(base)+1:]
        else: return False
    else:
        local = relpath
    if not local: return False
    if rule.get("dir_only") and not is_dir:
        return False
    anchored = pat.startswith("/")
    raw = pat[1:] if anchored else pat
    anchored = anchored or ("/" in raw)
    if anchored:
        return _glob_match_path(raw, local, rule.get("case_sensitive", True))
    return any(_glob_match_path(raw, part, rule.get("case_sensitive", True)) for part in local.split("/"))

def _compile_ignore_files(base_path: Path, base_rel: str, warnings: list[str]) -> list[dict]:
    rules: list[dict] = []
    try: entries = list(base_path.iterdir())
    except OSError as exc:
        warnings.append(f"Cannot list {base_rel or '.'}: {exc}"); return rules
    ignore_paths = sorted((p for p in entries if p.is_file() and _is_ignored_rule_filename(p.name)), key=lambda p: p.name.casefold())
    for file in ignore_paths:
        kind = "stignore" if file.name.lower() == ".stignore" and base_rel == "" else "git"
        if file.name.lower() == ".stignore" and base_rel != "":
            warnings.append(f"{file}: Syncthing applies .stignore only at the sync-root; treating this nested file as Git-style patterns.")
            kind = "git"
        if kind == "git" and file.name.lower() not in (".gitignore", ".ignore", ".dockerignore", ".npmignore"):
            warnings.append(f"{file}: unknown ignore-file format; parsing supported Git-style subset. Review the rules before relying on exclusions.")
        try: lines = _safe_decode(file).splitlines()
        except OSError as exc:
            warnings.append(f"Cannot read ignore file {file}: {exc}"); continue
        if kind == "stignore":
            for no, line in enumerate(lines, 1):
                pat = line.strip()
                if not pat or pat.startswith("//"): continue
                if pat.startswith("#include"):
                    warnings.append(f"{file}:{no}: #include is not expanded by this generator; rule may be incomplete."); continue
                insensitive = False
                changed = True
                while changed:
                    changed = False
                    if pat.startswith("(?i)"): insensitive = True; pat = pat[4:]; changed = True
                    if pat.startswith("(?d)"): pat = pat[4:]; changed = True
                neg = pat.startswith("!")
                if neg: pat = pat[1:]
                if not pat: continue
                rules.append({"kind":"stignore", "pattern":pat, "negated":neg, "base":"", "case_sensitive":not insensitive, "line":f"{file}:{no}"})
            continue
        for no, raw in enumerate(lines, 1):
            pat = raw.rstrip()
            if not pat or pat.startswith("#"): continue
            if pat.startswith("\\#"): pat = pat[1:]
            neg = pat.startswith("!")
            if neg: pat = pat[1:]
            if not pat: continue
            if "\\" in pat:
                warnings.append(f"{file}:{no}: backslash escaping has partial support; check this pattern manually.")
            # Git treats trailing slash as directories only.
            dir_only = pat.endswith("/")
            if dir_only: pat = pat.rstrip("/")
            rules.append({"kind":"git", "pattern":pat, "negated":neg, "base":base_rel, "dir_only":dir_only, "case_sensitive":True, "line":f"{file}:{no}"})
    return rules


def _stignore_match(rule: dict, relpath: str, is_dir: bool) -> bool:
    pat = rule["pattern"]
    # Syncthing paths are relative to root. A trailing slash pattern means contents,
    # not the directory itself.
    if pat.endswith("/"):
        p = pat.rstrip("/")
        candidate = relpath
        if not rule.get("case_sensitive", True): p, candidate = p.casefold(), candidate.casefold()
        if candidate == p and is_dir: return False
        return candidate.startswith(p + "/")
    anchored = pat.startswith("/")
    p = pat[1:] if anchored else pat
    candidate = relpath
    if not rule.get("case_sensitive", True):
        p, candidate = p.lower(), candidate.lower()
    if anchored:
        return fnmatch.fnmatchcase(candidate, p) or candidate.startswith(p.rstrip("/") + "/")
    if fnmatch.fnmatchcase(candidate, p) or any(fnmatch.fnmatchcase(part, p) for part in candidate.split("/")):
        return True
    # An ignored directory ignores all of its descendants.
    parts = candidate.split("/")
    return any(fnmatch.fnmatchcase("/".join(parts[:i]), p) or fnmatch.fnmatchcase(parts[i-1], p) for i in range(1, len(parts)))


def _should_exclude(relpath: str, is_dir: bool, inherited_rules: list[dict], report: list[dict]) -> tuple[bool, str | None]:
    name = relpath.rsplit("/", 1)[-1]
    if is_dir and name.casefold() in DEFAULT_EXCLUDED_DIRS:
        return True, "built-in excluded directory"
    if _is_ignored_rule_filename(name):
        return True, "ignore-rule file"
    if name == MANIFEST_NAME:
        return True, "reserved resurrection manifest name"
    git_ignored = False; git_reason = None
    st_rules = [r for r in inherited_rules if r["kind"] == "stignore"]
    # Syncthing's first matching rule decides.
    for rule in st_rules:
        if _stignore_match(rule, relpath, is_dir):
            if rule["negated"]: git_ignored = git_ignored  # explicit include for this system only
            else: return True, f"Syncthing rule ({rule['line']})"
            break
    # Git-style rules: last matching rule wins, with nested files overriding parent files.
    for rule in inherited_rules:
        if rule["kind"] != "git": continue
        if _rule_match_git(rule, relpath, is_dir):
            git_ignored = not rule["negated"]
            git_reason = (f"ignore rule ({rule['line']})" if git_ignored else None)
    return (True, git_reason) if git_ignored else (False, None)


def _portable_path_problem(relpath: str) -> str | None:
    forbidden = set('<>:"|?*\\')
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1,10)), *(f"LPT{i}" for i in range(1,10))}
    for part in relpath.split("/"):
        if not part or any(ch in forbidden or ord(ch) < 32 for ch in part):
            return "name cannot be represented safely on Windows"
        if part.endswith((".", " ")) or part.split(".")[0].upper() in reserved:
            return "name is reserved/ambiguous on Windows"
    return None


def scan_project(root: Path, output_path: Path, generator_path: Path | None) -> tuple[list[dict], list[dict], list[str]]:
    included: list[dict] = []; excluded: list[dict] = []; warnings: list[str] = []
    output_resolved = output_path.resolve(strict=False)
    generator_resolved = generator_path.resolve(strict=False) if generator_path else None
    def walk(directory: Path, rel_dir: str, inherited: list[dict]):
        local = inherited + _compile_ignore_files(directory, rel_dir, warnings)
        try: entries = sorted(directory.iterdir(), key=lambda p: (p.name.casefold(), p.name))
        except OSError as exc:
            excluded.append({"path": rel_dir or ".", "reason": f"cannot access: {exc}"}); return
        for path in entries:
            rel = f"{rel_dir}/{path.name}" if rel_dir else path.name
            try: resolved = path.resolve(strict=False)
            except OSError: resolved = path.absolute()
            if resolved == output_resolved:
                excluded.append({"path":rel,"reason":"output script path"}); continue
            if generator_resolved and resolved == generator_resolved:
                excluded.append({"path":rel,"reason":"generator script (avoids embedding the generator in its own output)"}); continue
            portability_issue = _portable_path_problem(rel)
            if portability_issue:
                excluded.append({"path":rel,"reason":portability_issue}); continue
            try: st = path.lstat()
            except OSError as exc:
                excluded.append({"path":rel,"reason":f"cannot stat: {exc}"}); continue
            if stat.S_ISLNK(st.st_mode):
                excluded.append({"path":rel,"reason":"symbolic link (not followed)"}); continue
            is_dir = stat.S_ISDIR(st.st_mode)
            if not is_dir and not stat.S_ISREG(st.st_mode):
                excluded.append({"path":rel,"reason":"special filesystem entry"}); continue
            blocked, reason = _should_exclude(rel, is_dir, local, excluded)
            if blocked:
                excluded.append({"path":rel,"reason":reason or "ignore rule"}); continue
            item = {"path":rel, "kind":"dir" if is_dir else "file", "size":0 if is_dir else st.st_size,
                    "mtime":int(st.st_mtime), "mode":stat.S_IMODE(st.st_mode)}
            if is_dir:
                included.append(item)
                walk(path, rel, local)
            else:
                included.append(item)
    walk(root, "", [])
    included.sort(key=lambda x:(x["path"].casefold(), x["path"]))
    return included, excluded, warnings


def zip_project(root: Path, items: list[dict], zip_path: Path) -> tuple[list[dict], int]:
    final_manifest: list[dict] = []
    uncompressed_total = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as zf:
        for item in items:
            rel = item["path"]
            arcname = rel.replace(os.sep, "/")
            dt = time.localtime(item["mtime"])
            year = max(1980, min(2107, dt.tm_year))
            date_time = (year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec - dt.tm_sec % 2)
            if item["kind"] == "dir":
                zi = zipfile.ZipInfo(arcname.rstrip("/") + "/", date_time)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = (stat.S_IFDIR | item["mode"]) << 16
                zf.writestr(zi, b"", compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
                final_manifest.append({**item, "sha256": None})
                continue
            path = root / Path(*PurePosixPath(rel).parts)
            digest = hashlib.sha256(); bytes_written = 0
            zi = zipfile.ZipInfo(arcname, date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (stat.S_IFREG | item["mode"]) << 16
            with path.open("rb") as src, zf.open(zi, "w", force_zip64=True) as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk: break
                    digest.update(chunk); dst.write(chunk); bytes_written += len(chunk)
            if bytes_written != item["size"]:
                raise RuntimeError(f"File changed while packaging: {rel} (expected {item['size']} bytes, read {bytes_written})")
            final_manifest.append({**item, "size":bytes_written, "sha256":digest.hexdigest()})
            uncompressed_total += bytes_written
        manifest_doc = {"format":"ProjectResurrection", "version":FORMAT_VERSION,
                        "created_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "hash":"SHA-256", "items":final_manifest}
        zf.writestr(MANIFEST_NAME, json.dumps(manifest_doc, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"),
                    compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return final_manifest, uncompressed_total

PY_RESTORER_HEAD = r'''#!/usr/bin/env python3
# Project Resurrection — standalone offline restorer. Python 3.9+, standard library only.
import base64, getpass, hashlib, hmac, json, os, secrets, shutil, stat, struct, sys, tempfile, zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

APP_NAME = "Project Resurrection"
MAGIC = b"PRJRX2\0\0"
HEADER_LEN = 44
TAG_LEN = 32
MANIFEST_NAME = ".resurrection-manifest.json"
DATA_BEGIN = "#--RESURRECTION-DATA-BEGIN--"
DATA_END = "#--RESURRECTION-DATA-END--"
KDF_ITERATIONS_MIN = 100_000
@@AES_SOURCE@@

def _derive(password, salt, iterations):
    raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)
    return raw[:32], raw[32:]

def _payload_to_file(script_path, out_path):
    active = False; saw_begin = False; saw_end = False
    with script_path.open("r", encoding="utf-8", errors="strict") as src, out_path.open("wb") as dst:
        for line in src:
            stripped = line.rstrip("\r\n")
            if stripped == DATA_BEGIN: active = True; saw_begin = True; continue
            if stripped == DATA_END: saw_end = True; active = False; break
            if active:
                if not stripped.startswith("#RDATA:"): raise ValueError("Malformed embedded payload line")
                chunk = stripped[7:]
                try: dst.write(base64.b64decode(chunk, validate=True))
                except Exception as exc: raise ValueError("Malformed Base64 payload") from exc
    if not saw_begin or not saw_end or out_path.stat().st_size < HEADER_LEN + 16 + TAG_LEN:
        raise ValueError("No complete resurrection payload was found in this script")

def _decrypt_envelope(envelope_path, zip_path, password):
    size = envelope_path.stat().st_size
    if size < HEADER_LEN + 16 + TAG_LEN: raise ValueError("Payload is truncated")
    with envelope_path.open("rb") as f:
        header = f.read(HEADER_LEN)
        if header[:8] != MAGIC: raise ValueError("Unrecognized archive format")
        iterations = struct.unpack(">I", header[8:12])[0]
        if not KDF_ITERATIONS_MIN <= iterations <= 10_000_000: raise ValueError("Unsafe/unsupported KDF iteration count")
        salt, iv = header[12:28], header[28:44]
        ciphertext_len = size - HEADER_LEN - TAG_LEN
        if ciphertext_len <= 0 or ciphertext_len % 16: raise ValueError("Invalid encrypted payload length")
        enc_key, mac_key = _derive(password, salt, iterations)
        mac = hmac.new(mac_key, header, hashlib.sha256)
        f.seek(HEADER_LEN); remaining = ciphertext_len
        while remaining:
            block = f.read(min(1024 * 1024, remaining))
            if not block: raise ValueError("Payload ended unexpectedly")
            mac.update(block); remaining -= len(block)
        tag = f.read(TAG_LEN)
        if not hmac.compare_digest(mac.digest(), tag): raise ValueError("Password incorrect or payload authentication failed")
        f.seek(HEADER_LEN)
        # Stream CBC decryption to a temporary file, keeping at most one chunk in RAM.
        words = _aes_expand_key(enc_key); prev = iv; remaining = ciphertext_len; pending = b""
        with zip_path.open("wb") as out:
            while remaining:
                chunk = f.read(min(1024 * 1024, remaining)); remaining -= len(chunk)
                pending += chunk
                usable = (len(pending) // 16) * 16
                # Keep the final ciphertext block to validate/remove PKCS#7 padding.
                if remaining == 0: usable = max(0, usable - 16)
                if usable:
                    data = pending[:usable]; pending = pending[usable:]
                    plain = bytearray()
                    for pos in range(0, len(data), 16):
                        cblock = data[pos:pos+16]; pblock = _aes_decrypt_block(cblock, words)
                        plain.extend(a ^ b for a,b in zip(pblock, prev)); prev = cblock
                    out.write(plain)
            if len(pending) != 16: raise ValueError("Invalid final AES block")
            last = _aes_decrypt_block(pending, words)
            plain_last = bytes(a ^ b for a,b in zip(last, prev))
            pad = plain_last[-1]
            if pad < 1 or pad > 16 or plain_last[-pad:] != bytes([pad]) * pad: raise ValueError("Invalid encrypted padding")
            out.write(plain_last[:-pad])

def _validate_relpath(name):
    if not isinstance(name, str) or not name or "\x00" in name: raise ValueError("Invalid path in manifest")
    norm = name.replace("\\", "/")
    posix = PurePosixPath(norm); win = PureWindowsPath(norm)
    if norm.startswith("/") or posix.is_absolute() or win.is_absolute() or win.drive: raise ValueError("Absolute path rejected: " + name)
    parts = norm.split("/")
    if any(part in ("", ".", "..") for part in parts): raise ValueError("Unsafe path component rejected: " + name)
    forbidden = set('<>:"|?*')
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1,10)), *(f"LPT{i}" for i in range(1,10))}
    for part in parts:
        if any(ch in forbidden or ord(ch) < 32 for ch in part) or part.endswith((".", " ")) or part.split(".")[0].upper() in reserved:
            raise ValueError("Path is not portable/safe on Windows: " + name)
    return norm

def _restore(zip_path, destination):
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        if names.count(MANIFEST_NAME) != 1: raise ValueError("Archive manifest is missing or duplicated")
        manifest = json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
        if manifest.get("format") != "ProjectResurrection" or manifest.get("version") != 2: raise ValueError("Unsupported manifest")
        expected = { }
        for item in manifest.get("items", []):
            rel = _validate_relpath(item.get("path"))
            if rel in expected: raise ValueError("Duplicate manifest path: " + rel)
            if item.get("kind") not in ("file", "dir"): raise ValueError("Unknown item type")
            expected[rel] = item
        archive_paths = set()
        for info in zf.infolist():
            if info.filename == MANIFEST_NAME: continue
            raw = info.filename.rstrip("/")
            rel = _validate_relpath(raw)
            if rel in archive_paths: raise ValueError("Duplicate path in archive: " + rel)
            archive_paths.add(rel)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode): raise ValueError("Symbolic link entry rejected: " + rel)
            if rel not in expected: raise ValueError("Unmanifested archive entry: " + rel)
        if archive_paths != set(expected):
            missing = sorted(set(expected) - archive_paths)
            extra = sorted(archive_paths - set(expected))
            raise ValueError("Archive/manifest mismatch. Missing=" + repr(missing[:5]) + " extra=" + repr(extra[:5]))
        if destination.exists(): raise FileExistsError("Destination already exists; refusing to overwrite: " + str(destination))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir()
        restored = []; total = 0
        try:
            for rel, item in sorted(expected.items(), key=lambda kv:(kv[0].count("/"), kv[0].casefold(), kv[0])):
                target = destination.joinpath(*PurePosixPath(rel).parts)
                if not target.resolve(strict=False).is_relative_to(destination.resolve()): raise ValueError("Path escaped destination: " + rel)
                if item["kind"] == "dir":
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists(): raise FileExistsError("Refusing to overwrite: " + str(target))
                h = hashlib.sha256(); written = 0
                with zf.open(rel, "r") as src, target.open("xb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk: break
                        dst.write(chunk); h.update(chunk); written += len(chunk)
                if written != item.get("size") or not hmac.compare_digest(h.hexdigest(), item.get("sha256", "")):
                    raise ValueError("SHA-256/size verification failed: " + rel)
                try:
                    mtime = int(item.get("mtime", 0))
                    os.utime(target, (mtime, mtime))
                except (OSError, OverflowError, ValueError): pass
                try: os.chmod(target, int(item.get("mode", 0o644)) & 0o777)
                except OSError: pass
                restored.append((rel, written, h.hexdigest())); total += written
            for rel, item in sorted(expected.items(), key=lambda kv: kv[0].count("/"), reverse=True):
                if item["kind"] == "dir":
                    target = destination.joinpath(*PurePosixPath(rel).parts)
                    try:
                        mtime = int(item.get("mtime", 0))
                        os.utime(target, (mtime, mtime))
                    except (OSError, OverflowError, ValueError): pass
                    try: os.chmod(target, int(item.get("mode", 0o755)) & 0o777)
                    except OSError: pass
            report = {"result":"success", "destination":str(destination), "files_verified":len(restored),
                      "directories_restored":sum(1 for x in expected.values() if x["kind"] == "dir"),
                      "bytes_restored":total, "hash":"SHA-256", "files":[{"path":p,"bytes":n,"sha256":d} for p,n,d in restored]}
            report_path = destination.parent / (destination.name + "-resurrection-report.json")
            report["report_path"] = str(report_path)
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            return report
        except Exception:
            # Preserve partial recovery for diagnosis; never silently delete recovered user data.
            raise

def main():
    print("\nProject Resurrection — offline restore\n")
    script = Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix="project-resurrection-") as td:
        envelope = Path(td) / "payload.bin"; archive = Path(td) / "decrypted.zip"
        try:
            _payload_to_file(script, envelope)
            password = getpass.getpass("Archive password: ")
            if not password: raise ValueError("An empty password is not accepted")
            _decrypt_envelope(envelope, archive, password)
            del password
            default_name = script.stem.replace("-Resurrection", "") + "-restored"
            dest_text = input("New destination directory [" + str(Path.cwd() / default_name) + "]: ").strip()
            destination = Path(dest_text).expanduser() if dest_text else Path.cwd() / default_name
            destination = destination.absolute()
            report = _restore(archive, destination)
            print("\nRestore complete. SHA-256 verified for", report["files_verified"], "files.")
            print("Bytes restored:", report["bytes_restored"])
            print("Report:", report["report_path"])
        except Exception as exc:
            print("\nRESTORE FAILED:", exc, file=sys.stderr)
            print("No existing files were intentionally overwritten. If restoration began, partial files remain at the chosen destination for inspection.", file=sys.stderr)
            raise SystemExit(1)

if __name__ == "__main__":
    main()
#--RESURRECTION-DATA-BEGIN--
@@DATA@@
#--RESURRECTION-DATA-END--
'''

PS_RESTORER_TEMPLATE = r'''# Project Resurrection - standalone PowerShell restorer (Windows PowerShell 5.1+ / PowerShell 7+)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$DataBegin = '#--RESURRECTION-DATA-BEGIN--'
$DataEnd = '#--RESURRECTION-DATA-END--'
$Magic = [System.Text.Encoding]::ASCII.GetBytes("PRJRX2`0`0")
$ManifestName = '.resurrection-manifest.json'
function Read-Payload([string]$ScriptPath, [string]$OutPath) {
    $inside = $false; $sawBegin = $false; $sawEnd = $false
    $stream = [System.IO.File]::Open($OutPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        foreach ($line in [System.IO.File]::ReadLines($ScriptPath)) {
            if ($line -ceq $DataBegin) { $inside = $true; $sawBegin = $true; continue }
            if ($line -ceq $DataEnd) { $sawEnd = $true; break }
            if ($inside) {
                if (!$line.StartsWith('#RDATA:', [System.StringComparison]::Ordinal)) { throw 'Malformed embedded payload line.' }
                $raw = [Convert]::FromBase64String($line.Substring(7))
                $stream.Write($raw, 0, $raw.Length)
            }
        }
    } finally { $stream.Dispose() }
    if (!$sawBegin -or !$sawEnd -or (Get-Item $OutPath).Length -lt 96) { throw 'No complete resurrection payload was found.' }
}
function Derive-Key([string]$Password, [byte[]]$Salt, [int]$Iterations) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($bytes, $Salt, $Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return ,$derive.GetBytes(64) } finally { $derive.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
}
function Decrypt-Payload([string]$Envelope, [string]$ZipOut, [string]$Password) {
    $fs = [System.IO.File]::OpenRead($Envelope)
    try {
        if ($fs.Length -lt 96) { throw 'Payload is truncated.' }
        $header = New-Object byte[] 44; [void]$fs.Read($header, 0, 44)
        for ($i=0; $i -lt 8; $i++) { if ($header[$i] -ne $Magic[$i]) { throw 'Unrecognized archive format.' } }
        $iterations = ([int]$header[8] -shl 24) -bor ([int]$header[9] -shl 16) -bor ([int]$header[10] -shl 8) -bor [int]$header[11]
        if ($iterations -lt 100000 -or $iterations -gt 10000000) { throw 'Unsafe/unsupported KDF iteration count.' }
        $salt = New-Object byte[] 16; [Array]::Copy($header,12,$salt,0,16)
        $iv = New-Object byte[] 16; [Array]::Copy($header,28,$iv,0,16)
        $cipherLen = [long]$fs.Length - 44 - 32
        if ($cipherLen -le 0 -or ($cipherLen % 16) -ne 0) { throw 'Invalid encrypted payload length.' }
        $keys = Derive-Key $Password $salt $iterations
        $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$keys[32..63])
        try {
            [void]$hmac.TransformBlock($header,0,$header.Length,$header,0)
            $remaining = $cipherLen; $buffer = New-Object byte[] (1024 * 1024)
            while ($remaining -gt 0) {
                $want = [int][Math]::Min($buffer.Length,$remaining); $read = $fs.Read($buffer,0,$want)
                if ($read -le 0) { throw 'Payload ended unexpectedly.' }
                [void]$hmac.TransformBlock($buffer,0,$read,$buffer,0); $remaining -= $read
            }
            [void]$hmac.TransformFinalBlock((New-Object byte[] 0),0,0)
            $computed = $hmac.Hash; $tag = New-Object byte[] 32; [void]$fs.Read($tag,0,32)
            $diff = 0
            for ($i=0; $i -lt 32; $i++) { $diff = $diff -bor ($computed[$i] -bxor $tag[$i]) }
            if ($diff -ne 0) { throw 'Password incorrect or payload authentication failed.' }
        } finally { $hmac.Dispose() }
        # Copy authenticated ciphertext to a temporary file, then use .NET AES-CBC/PKCS7.
        $fs.Position = 44; $cipherPath = $Envelope + '.cipher.tmp'
        $cfs = [System.IO.File]::Open($cipherPath,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
        try {
            $remaining = $cipherLen; $buffer = New-Object byte[] (1024 * 1024)
            while ($remaining -gt 0) { $want=[int][Math]::Min($buffer.Length,$remaining); $read=$fs.Read($buffer,0,$want); if($read -le 0){throw 'Payload ended unexpectedly.'}; $cfs.Write($buffer,0,$read); $remaining-=$read }
        } finally { $cfs.Dispose() }
        $aes = [System.Security.Cryptography.Aes]::Create(); $aes.KeySize=256; $aes.BlockSize=128; $aes.Mode='CBC'; $aes.Padding='PKCS7'
        $aes.Key = [byte[]]$keys[0..31]; $aes.IV = $iv
        $input = [System.IO.File]::OpenRead($cipherPath); $output = [System.IO.File]::Open($ZipOut,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
        try { $crypto = [System.Security.Cryptography.CryptoStream]::new($output,$aes.CreateDecryptor(),[System.Security.Cryptography.CryptoStreamMode]::Write); try { $input.CopyTo($crypto); $crypto.FlushFinalBlock() } finally { $crypto.Dispose() } }
        finally { $input.Dispose(); $output.Dispose(); $aes.Dispose(); Remove-Item -LiteralPath $cipherPath -Force -ErrorAction SilentlyContinue; [Array]::Clear($keys,0,$keys.Length) }
    } finally { $fs.Dispose() }
}
function Validate-RelativePath([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains([char]0)) { throw 'Invalid path in manifest.' }
    $n = $Name.Replace('\','/')
    if ($n.StartsWith('/') -or $n -match '^[A-Za-z]:' -or (($n -split '/') -contains '..') -or (($n -split '/') -contains '.')) { throw "Unsafe path rejected: $Name" }
    return $n
}
function Restore-Zip([string]$ZipPath, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $m = @($zip.Entries | Where-Object { $_.FullName -ceq $ManifestName })
        if ($m.Count -ne 1) { throw 'Archive manifest is missing or duplicated.' }
        $reader = New-Object System.IO.StreamReader($m[0].Open(),[System.Text.Encoding]::UTF8)
        try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        if ($manifest.format -ne 'ProjectResurrection' -or $manifest.version -ne 2) { throw 'Unsupported manifest.' }
        $expected = @{}
        foreach ($item in $manifest.items) { $rel=Validate-RelativePath ([string]$item.path); if($expected.ContainsKey($rel)){throw "Duplicate manifest path: $rel"}; if($item.kind -notin @('file','dir')){throw 'Unknown item type.'}; $expected[$rel]=$item }
        $seen = @{}
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -ceq $ManifestName) { continue }
            $rel = Validate-RelativePath ($entry.FullName.TrimEnd('/'))
            if ($seen.ContainsKey($rel)) { throw "Duplicate archive path: $rel" }
            $seen[$rel] = $true
            if (!$expected.ContainsKey($rel)) { throw "Unmanifested archive entry: $rel" }
        }
        foreach ($rel in $expected.Keys) { if (!$seen.ContainsKey($rel)) { throw "Manifest entry missing from archive: $rel" } }
        if (Test-Path -LiteralPath $Destination) { throw "Destination already exists; refusing to overwrite: $Destination" }
        $parent = Split-Path -Parent $Destination; if ($parent -and !(Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
        [void](New-Item -ItemType Directory -Path $Destination)
        $destFull = [System.IO.Path]::GetFullPath($Destination).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        $verified = 0; [long]$total = 0; $reportFiles = New-Object System.Collections.Generic.List[object]
        try {
            foreach ($rel in @($expected.Keys | Sort-Object { ($_ -split '/').Count }, { $_.ToLowerInvariant() })) {
                $item=$expected[$rel]; $target=[System.IO.Path]::GetFullPath((Join-Path $Destination ($rel.Replace('/',[System.IO.Path]::DirectorySeparatorChar))))
                if (!$target.StartsWith($destFull,[System.StringComparison]::OrdinalIgnoreCase)) { throw "Path escaped destination: $rel" }
                if ($item.kind -eq 'dir') { if (!(Test-Path -LiteralPath $target)) { [void](New-Item -ItemType Directory -Path $target -Force) }; continue }
                $folder=Split-Path -Parent $target; if (!(Test-Path -LiteralPath $folder)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
                if (Test-Path -LiteralPath $target) { throw "Refusing to overwrite: $target" }
                $entry = @($zip.Entries | Where-Object { $_.FullName.TrimEnd('/') -ceq $rel })[0]
                $input=$entry.Open(); $output=[System.IO.File]::Open($target,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None); $sha=[System.Security.Cryptography.SHA256]::Create(); [long]$written=0
                try { $buf=New-Object byte[] (1024*1024); while(($read=$input.Read($buf,0,$buf.Length)) -gt 0){$output.Write($buf,0,$read); [void]$sha.TransformBlock($buf,0,$read,$buf,0); $written += $read}; [void]$sha.TransformFinalBlock((New-Object byte[] 0),0,0); $digest=([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant() }
                finally { $input.Dispose(); $output.Dispose(); $sha.Dispose() }
                if ($written -ne [long]$item.size -or $digest -cne [string]$item.sha256) { throw "SHA-256/size verification failed: $rel" }
                try { [System.IO.File]::SetLastWriteTimeUtc($target, [DateTimeOffset]::FromUnixTimeSeconds([long]$item.mtime).UtcDateTime) } catch { }
                $verified++; $total += $written; $reportFiles.Add([pscustomobject]@{path=$rel;bytes=$written;sha256=$digest})
            }
            foreach ($rel in @($expected.Keys | Sort-Object { ($_ -split '/').Count } -Descending)) {
                $item = $expected[$rel]
                if ($item.kind -eq 'dir') {
                    $dirTarget = [System.IO.Path]::GetFullPath((Join-Path $Destination ($rel.Replace('/',[System.IO.Path]::DirectorySeparatorChar))))
                    try { [System.IO.Directory]::SetLastWriteTimeUtc($dirTarget, [DateTimeOffset]::FromUnixTimeSeconds([long]$item.mtime).UtcDateTime) } catch { }
                }
            }
            $report=[ordered]@{result='success';destination=$Destination;files_verified=$verified;directories_restored=@($manifest.items|Where-Object kind -eq 'dir').Count;bytes_restored=$total;hash='SHA-256';files=$reportFiles}
            $reportPath = Join-Path (Split-Path -Parent $Destination) ((Split-Path -Leaf $Destination) + '-resurrection-report.json')
            $report.report_path = $reportPath
            $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
            Write-Host "Restore complete. SHA-256 verified for $verified files." -ForegroundColor Green
            Write-Host "Bytes restored: $total"
            Write-Host "Report: $reportPath"
        } catch { Write-Warning 'Restoration stopped. Any partial files are left in the destination for inspection.'; throw }
    } finally { $zip.Dispose() }
}
try {
    Write-Host "`nProject Resurrection - offline restore`n" -ForegroundColor Cyan
    $scriptPath = $PSCommandPath
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('project-resurrection-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $temp)
    try {
        $envPath=Join-Path $temp 'payload.bin'; $zipPath=Join-Path $temp 'decrypted.zip'
        Read-Payload $scriptPath $envPath
        $secure=Read-Host 'Archive password' -AsSecureString
        $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $password=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        if ([string]::IsNullOrEmpty($password)) { throw 'An empty password is not accepted.' }
        Decrypt-Payload $envPath $zipPath $password; $password=$null
        $base = [System.IO.Path]::GetFileNameWithoutExtension($scriptPath) -replace '-Resurrection$',''
        $default = Join-Path (Get-Location) ($base + '-restored')
        $answer=Read-Host "New destination directory [$default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer=$default }
        Restore-Zip $zipPath ([System.IO.Path]::GetFullPath($answer))
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
} catch { Write-Error ("RESTORE FAILED: " + $_.Exception.Message); exit 1 }
#--RESURRECTION-DATA-BEGIN--
@@DATA@@
#--RESURRECTION-DATA-END--
'''


def build_script(root: Path, output_path: Path, fmt: str, password: str, generator_path: Path | None) -> dict:
    warnings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="project-resurrection-build-") as td:
        td_path = Path(td); zip_path = td_path / "project.zip"; envelope_path = td_path / "payload.bin"
        items, excluded, warnings = scan_project(root, output_path, generator_path)
        case_paths: dict[str, str] = {}
        for item in items:
            folded = item["path"].casefold()
            prior = case_paths.get(folded)
            if prior is not None and prior != item["path"]:
                raise RuntimeError(f"Case-insensitive path collision makes this project non-portable to Windows: {prior!r} and {item['path']!r}")
            case_paths[folded] = item["path"]
        if not items:
            raise RuntimeError("No files or directories remain after exclusions; refusing to create an empty resurrection script.")
        final_manifest, uncompressed = zip_project(root, items, zip_path)
        zip_size = zip_path.stat().st_size
        envelope_size, cipher_size = encrypt_file(zip_path, envelope_path, password)
        if fmt == "py":
            template = PY_RESTORER_HEAD.replace("@@AES_SOURCE@@", AES_SOURCE)
        elif fmt == "ps1":
            template = PS_RESTORER_TEMPLATE
        else: raise ValueError("format must be py or ps1")
        before, marker, after = template.partition("@@DATA@@")
        if not marker: raise RuntimeError("Internal template error: payload insertion point is missing")
        # Write Base64 comments incrementally; don't keep a second copy of a huge script in RAM.
        staging = output_path.with_name(output_path.name + ".writing-" + secrets.token_hex(5))
        try:
            # Windows PowerShell 5.1 treats UTF-8 without a BOM as the active ANSI code page.
            # Use utf-8-sig for .ps1 output so smart quotes / punctuation cannot be mis-tokenized.
            output_encoding = "utf-8-sig" if fmt == "ps1" else "utf-8"
            with staging.open("w", encoding=output_encoding, newline="\n") as dest:
                dest.write(before)
                for data_line in _data_lines(envelope_path):
                    dest.write(data_line); dest.write("\n")
                dest.write(after[1:] if after.startswith("\n") else after); dest.write("\n")
            if fmt == "py":
                try: staging.chmod(staging.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                except OSError: pass
            os.replace(staging, output_path)
        finally:
            try: staging.unlink()
            except FileNotFoundError: pass
        return {"included":len(final_manifest),"files":sum(x["kind"]=="file" for x in final_manifest),
                "directories":sum(x["kind"]=="dir" for x in final_manifest),"excluded":len(excluded),
                "source_bytes":uncompressed,"zip_bytes":zip_size,"encrypted_bytes":envelope_size,
                "script_bytes":output_path.stat().st_size,"script":str(output_path),"excluded_items":excluded,"warnings":warnings}


def _data_lines(path: Path):
    # 3,072 input bytes produce 4,096 Base64 characters; each line decodes independently.
    with path.open("rb") as f:
        while True:
            block=f.read(3072)
            if not block: break
            yield "#RDATA:" + base64.b64encode(block).decode("ascii")


def main() -> int:
    print("\n=== Project Resurrection Generator ===")
    print("Standalone encrypted self-restoring scripts | offline | standard-library generator")
    print("\nThis does not delete, move, or modify source files.")
    try:
        src_text = input("Project/source directory path: ").strip().strip('"')
        if not src_text: raise ValueError("A source directory is required")
        root = Path(src_text).expanduser().resolve(strict=True)
        if not root.is_dir(): raise ValueError("The source path is not a directory")
        print("\nChoose output format:")
        print("  1) Python .py (Python 3.9+; standard library only; cross-platform, including Termux)")
        print("  2) PowerShell .ps1 (Windows PowerShell 5.1+ / PowerShell 7+)")
        choice = input("Format [1]: ").strip().lower() or "1"
        fmt = "py" if choice in ("1", "py", ".py", "python") else "ps1" if choice in ("2", "ps1", ".ps1", "powershell", "power shell") else None
        if not fmt: raise ValueError("Choose 1 for Python or 2 for PowerShell")
        default_out = Path.cwd() / (root.name + "-Resurrection." + fmt)
        out_text = input(f"Output script path [{default_out}]: ").strip().strip('"')
        output = Path(out_text).expanduser().absolute() if out_text else default_out.absolute()
        if output.resolve(strict=False) == root.resolve(): raise ValueError("Output path must be a file, not the source directory")
        if output.resolve(strict=False) == Path(__file__).resolve(): raise ValueError("Output path cannot overwrite the generator itself")
        if output.exists():
            ans = input(f"Output already exists: {output}\nReplace that output script? [y/N]: ").strip().lower()
            if ans not in ("y", "yes"): raise RuntimeError("Cancelled; existing output left untouched")
        output.parent.mkdir(parents=True, exist_ok=True)
        password = getpass.getpass("Set archive password (12+ characters recommended): ")
        if not password: raise ValueError("An empty password is not accepted")
        confirm = getpass.getpass("Confirm archive password: ")
        if not hmac.compare_digest(password, confirm): raise ValueError("Passwords did not match")
        if len(password) < 8: print("WARNING: Password is short. A long unique password is strongly recommended.")
        output.parent.mkdir(parents=True, exist_ok=True)
        stats = build_script(root, output, fmt, password, Path(__file__).resolve())
        password = confirm = ""
        print("\nBUILD COMPLETE")
        print(f"Output script:        {stats['script']}")
        print(f"Output format:        .{fmt}")
        print(f"Included items:       {stats['included']} ({stats['files']} files, {stats['directories']} directories)")
        print(f"Excluded items:       {stats['excluded']}")
        print(f"Source file bytes:    {stats['source_bytes']:,}")
        print(f"Compressed ZIP bytes: {stats['zip_bytes']:,}")
        print(f"Encrypted bytes:      {stats['encrypted_bytes']:,}")
        print(f"Final script bytes:   {stats['script_bytes']:,}")
        print(f"KDF: PBKDF2-HMAC-SHA256 ({KDF_ITERATIONS:,} iterations); encryption: AES-256-CBC + HMAC-SHA256; file hashes: SHA-256")
        if stats["warnings"]:
            print("\nIGNORE-FILE WARNINGS")
            for w in stats["warnings"]: print(" - " + w)
        print("\nExcluded entries (first 60):")
        for x in stats["excluded_items"][:60]: print(f" - {x['path']}: {x['reason']}")
        if len(stats["excluded_items"]) > 60: print(f" ... and {len(stats['excluded_items'])-60} more")
        print("\nKeep at least one separate backup of important data. The script is text-only, but Base64 makes it larger than the encrypted payload.")
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr); return 130
    except Exception as exc:
        print("\nBUILD FAILED:", exc, file=sys.stderr); return 1

if __name__ == "__main__":
    raise SystemExit(main())
