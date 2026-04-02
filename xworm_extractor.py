#!/usr/bin/env python3
"""
XWorm V3.x Configuration Extractor
====================================
Extracts and decrypts the embedded C2 configuration from unobfuscated
XWorm V3.x PE32 .NET assemblies without executing the sample.

How it works
------------
1. Parses the .NET #US (User Strings) metadata stream directly from the
   PE binary — no external tools required.
2. Classifies strings:
     - Base64 candidates  : likely AES-encrypted config values
     - Mutex candidates   : likely the plaintext key seed
3. For every Mutex candidate, derives an AES-256-ECB key using XWorm's
   own MD5 scheme and attempts to decrypt all Base64 candidates.
4. Scores each candidate by how many decrypted values are valid UTF-8
   printable strings and picks the best match.
5. Reports the configuration in a human-readable table or JSON.

Encryption scheme (XWorm V3.x)
-------------------------------
    md5   = MD5( UTF-8(mutex) )          # 16 bytes
    key   = md5[0:16] + md5[0:16]        # naive concatenation…
    BUT:  Array.Copy(md5, 0, key, 15, 16) — the second copy starts at
          byte 15, so key[15:31] = md5[0:16], leaving key[31] = 0x00.
    mode  = AES-256-ECB, PKCS7 padding

Limitations
-----------
- XWorm V3.x only  — V5+ and V6+ have been reported to use different
  key-derivation and/or cipher configurations.
- Requires unobfuscated builds. ConfuserEx / .NET Reactor obfuscated
  samples must be deobfuscated first.
- Mutex identification is heuristic: non-Base64, printable, 4-64 chars.
  A mutex that coincidentally looks like Base64 would be missed, though
  the brute-force fallback (try every candidate) mitigates this.
- Only the #US stream is inspected. Future XWorm versions that store
  config in resources, embedded files, or #Blob would need extra logic.

Requirements
------------
    pip install cryptography      (already present on REMnux)

Usage
-----
    python3 xworm_extractor.py <sample.exe>
    python3 xworm_extractor.py <sample.exe> --verbose
    python3 xworm_extractor.py <sample.exe> --json
    python3 xworm_extractor.py <sample.exe> --out report.json --json
"""

import sys
import os
import re
import json
import struct
import base64
import hashlib
import argparse
from pathlib import Path

# ── optional: pretty colours in terminal ────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_OK    = Fore.GREEN
    C_WARN  = Fore.YELLOW
    C_ERR   = Fore.RED
    C_HEAD  = Fore.CYAN
    C_RESET = Style.RESET_ALL
except ImportError:
    C_OK = C_WARN = C_ERR = C_HEAD = C_RESET = ""

# ── AES via cryptography package ────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# ── known XWorm V3.x config field order (positional in the Settings class) ──
# The first N encrypted strings in the #US stream map to these fields.
FIELD_NAMES = ["Host", "Port", "KEY", "SPL", "USBNM"]

BANNER = f"""{C_HEAD}
  ╔══════════════════════════════════════════════════╗
  ║      XWorm V3.x Configuration Extractor          ║
  ║      Method : static / .NET #US stream parsing   ║
  ╚══════════════════════════════════════════════════╝
{C_RESET}"""


# ═══════════════════════════════════════════════════════════════════════════
# PE / .NET metadata parsing
# ═══════════════════════════════════════════════════════════════════════════

class PEParseError(Exception):
    pass


def _rva_to_offset(data: bytes, rva: int, sections: list) -> int:
    """Convert a Relative Virtual Address to a raw file offset."""
    for va, raw_off, vsize, rsize in sections:
        span = max(vsize, rsize)
        if va <= rva < va + span:
            return raw_off + (rva - va)
    raise PEParseError(f"RVA 0x{rva:08x} not found in any section")


def _parse_sections(data: bytes, pe_offset: int, num_sections: int,
                    opt_header_size: int) -> list:
    """Return list of (virtual_address, raw_offset, virtual_size, raw_size)."""
    sections = []
    sec_table_off = pe_offset + 4 + 20 + opt_header_size
    for i in range(num_sections):
        off = sec_table_off + i * 40
        vsize    = struct.unpack_from("<I", data, off + 8)[0]
        vaddr    = struct.unpack_from("<I", data, off + 12)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_off  = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((vaddr, raw_off, vsize, raw_size))
    return sections


def _find_metadata_offset(data: bytes) -> int:
    """
    Walk the PE header to find the .NET CLR metadata header (BSJB).

    PE structure path:
        DOS header → e_lfanew → PE sig + COFF header + Optional header
        → DataDirectory[14] (COM descriptor / CLR header RVA)
        → CLR header → MetaData RVA → BSJB
    """
    if data[:2] != b"MZ":
        raise PEParseError("Not a PE file (missing MZ signature)")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEParseError("PE signature not found")

    pe = e_lfanew
    num_sections     = struct.unpack_from("<H", data, pe + 6)[0]
    opt_header_size  = struct.unpack_from("<H", data, pe + 20)[0]
    magic            = struct.unpack_from("<H", data, pe + 24)[0]

    # DataDirectory[14] offset within the Optional Header
    # PE32  (magic 0x10b): standard(28) + windows-specific(68) + 14*8 = 208
    # PE32+ (magic 0x20b): standard(24) + windows-specific(88) + 14*8 = 224
    if magic == 0x10B:      # PE32
        clr_dd_off = pe + 24 + 208
    elif magic == 0x20B:    # PE32+
        clr_dd_off = pe + 24 + 224
    else:
        raise PEParseError(f"Unknown PE magic: 0x{magic:04x}")

    clr_rva = struct.unpack_from("<I", data, clr_dd_off)[0]
    if clr_rva == 0:
        raise PEParseError("No CLR data directory — not a .NET assembly")

    sections = _parse_sections(data, pe, num_sections, opt_header_size)
    clr_off  = _rva_to_offset(data, clr_rva, sections)

    # CLR header layout: Cb(4), Major(2), Minor(2), MetaDataRVA(4), ...
    metadata_rva = struct.unpack_from("<I", data, clr_off + 8)[0]
    return _rva_to_offset(data, metadata_rva, sections)


def _read_compressed_uint(data: bytes, offset: int) -> tuple[int, int]:
    """
    Read a .NET metadata compressed unsigned integer.
    Returns (value, bytes_consumed).
    Spec: ECMA-335 §II.23.2
    """
    b0 = data[offset]
    if b0 & 0x80 == 0:
        return b0, 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | data[offset + 1], 2
    if b0 & 0xE0 == 0xC0:
        return (((b0 & 0x1F) << 24)
                | (data[offset + 1] << 16)
                | (data[offset + 2] << 8)
                |  data[offset + 3]), 4
    raise PEParseError(f"Invalid compressed integer at offset 0x{offset:x}")


def extract_us_strings(filepath: str) -> list[str]:
    """
    Parse the .NET #US (User Strings) stream from a PE binary and return
    all non-empty UTF-16LE strings as a list of Python str objects.

    The #US stream stores strings referenced by `ldstr` IL instructions —
    these are the runtime string literals, including XWorm config values.
    """
    data = Path(filepath).read_bytes()
    meta_off = _find_metadata_offset(data)

    # BSJB metadata header
    if data[meta_off:meta_off + 4] != b"BSJB":
        raise PEParseError("BSJB metadata signature not found")

    # Skip: signature(4) + major(2) + minor(2) + reserved(4) + version_len(4)
    ver_len = struct.unpack_from("<I", data, meta_off + 12)[0]
    cursor = meta_off + 16 + ver_len
    cursor = (cursor + 3) & ~3      # align to 4 bytes

    # flags(2) + stream_count(2)
    stream_count = struct.unpack_from("<H", data, cursor + 2)[0]
    cursor += 4

    us_off = us_size = None
    for _ in range(stream_count):
        s_offset, s_size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        # Null-terminated name padded to 4-byte boundary
        name_start = cursor
        while data[cursor] != 0:
            cursor += 1
        name = data[name_start:cursor].decode("ascii", errors="replace")
        cursor += 1
        cursor = (cursor + 3) & ~3  # align

        if name == "#US":
            us_off  = meta_off + s_offset
            us_size = s_size
            break

    if us_off is None:
        raise PEParseError("#US stream not found in metadata")

    # Parse #US stream entries.
    # Each entry: compressed_length | utf-16le_bytes | terminal_byte
    # The length includes the terminal byte.  Entry at offset 0 is always 0.
    strings = []
    pos = us_off + 1           # skip the mandatory 0-byte at the start
    end = us_off + us_size

    while pos < end:
        if data[pos] == 0:
            pos += 1
            continue
        try:
            length, width = _read_compressed_uint(data, pos)
        except (PEParseError, IndexError):
            pos += 1
            continue

        pos += width
        if length == 0 or pos + length > end:
            continue

        # length bytes = (length-1) UTF-16LE chars + 1 terminal byte
        raw = data[pos: pos + length - 1]
        pos += length

        try:
            s = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            if s:
                strings.append(s)
        except Exception:
            pass

    return strings


# ═══════════════════════════════════════════════════════════════════════════
# String classification helpers
# ═══════════════════════════════════════════════════════════════════════════

_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


def is_base64_candidate(s: str) -> bool:
    """
    Return True if the string looks like an AES-encrypted Base64 config value.

    Heuristics (all must pass):
    - Length >= 16 (shortest plausible AES ciphertext = 1 block = 16 bytes → 24 B64 chars)
    - Length divisible by 4 (valid Base64)
    - Only Base64 alphabet characters
    - Successfully decodes without error
    - Decoded bytes length is a multiple of 16 (AES block size)
    """
    if len(s) < 16 or len(s) % 4 != 0:
        return False
    if not _B64_RE.match(s):
        return False
    try:
        decoded = base64.b64decode(s)
        return len(decoded) % 16 == 0 and len(decoded) > 0
    except Exception:
        return False


def is_mutex_candidate(s: str) -> bool:
    """
    Return True if the string could be a plaintext XWorm Mutex value.

    Heuristics:
    - Length 4–64 characters
    - Printable ASCII only
    - Not a pure Base64 string with valid padding
    - Not a known non-config string (e.g., single words like "INFO", "Error")
    - Not containing path separators or protocol schemes
    """
    if not (4 <= len(s) <= 64):
        return False
    if not all(0x20 <= ord(c) <= 0x7E for c in s):
        return False
    # Exclude obvious non-mutex patterns
    excluded = re.compile(
        r'(^https?://|^\\\\|\.exe$|\.dll$|\.ps1$|\.bat$'
        r'|^[A-Z]+$'                # all-caps words like "INFO", "ERROR"
        r'|^\d+$'                   # pure numbers
        r'|^[A-Za-z]+$'             # short dictionary words
        r'|\s)',                    # whitespace
        re.IGNORECASE
    )
    if excluded.search(s) and len(s) < 10:
        return False
    return True


# ═══════════════════════════════════════════════════════════════════════════
# AES decryption
# ═══════════════════════════════════════════════════════════════════════════

def derive_key(mutex: str) -> bytes:
    """
    XWorm V3.x AES key derivation.

    C# source (decompiled):
        byte[] array = new byte[32];
        byte[] sourceArray = MD5.ComputeHash(UTF8.GetBytes(mutex));
        Array.Copy(sourceArray, 0, array, 0,  16);  // first  half
        Array.Copy(sourceArray, 0, array, 15, 16);  // overlapping copy at offset 15

    The result is a 32-byte key where:
        key[0:15]  = md5[0:15]
        key[15:31] = md5[0:16]   (overwrites key[15] with md5[0])
        key[31]    = 0x00        (untouched from initialisation)
    """
    md5 = hashlib.md5(mutex.encode("utf-8")).digest()
    key = bytearray(32)
    key[0:16]  = md5
    key[15:31] = md5
    return bytes(key)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes | None:
    """AES-256-ECB decryption using the `cryptography` package."""
    if not _CRYPTO_AVAILABLE:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB(),
                        backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()
    except Exception:
        return None


def strip_padding(data: bytes) -> bytes:
    """
    Strip PKCS#7 padding, falling back to null-byte stripping.
    XWorm uses .NET's TransformFinalBlock which applies PKCS7.
    """
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and all(b == pad for b in data[-pad:]):
        return data[:-pad]
    return data.rstrip(b"\x00")


def is_printable_utf8(s: str) -> bool:
    """Return True if string contains only printable ASCII (config values are ASCII)."""
    return bool(s) and all(0x20 <= ord(c) <= 0x7E for c in s)


# ═══════════════════════════════════════════════════════════════════════════
# Config extraction logic
# ═══════════════════════════════════════════════════════════════════════════

def attempt_decrypt(mutex: str, b64_candidates: list[str]) -> dict:
    """
    Try to decrypt all Base64 candidates with the given mutex.
    Returns a dict mapping each Base64 string to its decrypted plaintext
    (only entries that produce valid printable UTF-8 are included).
    """
    key     = derive_key(mutex)
    results = {}
    for s in b64_candidates:
        ct       = base64.b64decode(s)
        pt_bytes = aes_ecb_decrypt(ct, key)
        if pt_bytes is None:
            continue
        pt_bytes = strip_padding(pt_bytes)
        try:
            pt = pt_bytes.decode("utf-8")
            if is_printable_utf8(pt):
                results[s] = pt
        except (UnicodeDecodeError, ValueError):
            pass
    return results


def build_config(decrypted: dict, b64_candidates: list[str],
                 mutex: str) -> dict:
    """
    Map decrypted values to XWorm V3.x field names by position.
    Encrypted values appear in the #US stream in the same order as
    the Settings class field declarations:
        Host, Port, KEY, SPL, USBNM
    """
    config = {"Mutex": mutex}
    field_idx = 0
    for b64 in b64_candidates:          # preserve discovery order
        if b64 in decrypted:
            name = FIELD_NAMES[field_idx] if field_idx < len(FIELD_NAMES) else f"Field_{field_idx}"
            config[name] = decrypted[b64]
            field_idx += 1
    return config


def extract_config(filepath: str, verbose: bool = False) -> dict:
    """
    Main extraction pipeline. Returns a result dict with keys:
        success     bool
        filepath    str
        sha256      str
        mutex       str | None
        config      dict   (field → plaintext value)
        all_strings list   (only when verbose=True)
        warnings    list[str]
        error       str | None
    """
    import hashlib as _hl

    result = {
        "success":     False,
        "filepath":    filepath,
        "sha256":      None,
        "mutex":       None,
        "config":      {},
        "warnings":    [],
        "error":       None,
    }

    # ── hash the file ────────────────────────────────────────────────────
    raw = Path(filepath).read_bytes()
    result["sha256"] = _hl.sha256(raw).hexdigest()

    if not _CRYPTO_AVAILABLE:
        result["error"] = (
            "cryptography package not available. "
            "Install with: pip install cryptography"
        )
        return result

    # ── parse .NET #US stream ────────────────────────────────────────────
    try:
        all_strings = extract_us_strings(filepath)
    except PEParseError as exc:
        result["error"] = f"PE/metadata parse error: {exc}"
        return result

    if verbose:
        result["all_strings"] = all_strings

    if not all_strings:
        result["error"] = "#US stream is empty — sample may be obfuscated or not .NET"
        return result

    # ── classify strings ─────────────────────────────────────────────────
    b64_candidates   = [s for s in all_strings if is_base64_candidate(s)]
    mutex_candidates = [s for s in all_strings if is_mutex_candidate(s)
                        and not is_base64_candidate(s)]

    if not b64_candidates:
        result["error"] = "No Base64-encoded config values found in #US stream"
        return result

    if not mutex_candidates:
        result["warnings"].append(
            "No clear Mutex candidates found — brute-forcing all #US strings"
        )
        mutex_candidates = [s for s in all_strings
                            if not is_base64_candidate(s) and len(s) >= 4]

    if verbose:
        result["b64_candidates"]   = b64_candidates
        result["mutex_candidates"] = mutex_candidates

    # ── try each mutex candidate; keep the best score ────────────────────
    best_score    = 0
    best_mutex    = None
    best_decrypted = {}

    for candidate in mutex_candidates:
        decrypted = attempt_decrypt(candidate, b64_candidates)
        score     = len(decrypted)
        if score > best_score:
            best_score     = score
            best_mutex     = candidate
            best_decrypted = decrypted

    if best_score == 0:
        result["error"] = (
            "No Mutex candidate produced valid decrypted output.\n"
            "Possible causes:\n"
            "  • Sample is obfuscated (empty/encrypted #US stream)\n"
            "  • XWorm version uses a different encryption scheme (e.g. V5+)\n"
            "  • Not an XWorm sample"
        )
        return result

    if best_score < len(FIELD_NAMES):
        result["warnings"].append(
            f"Only {best_score}/{len(FIELD_NAMES)} expected fields decrypted — "
            "may be a different XWorm build variant"
        )

    result["success"] = True
    result["mutex"]   = best_mutex
    result["config"]  = build_config(best_decrypted, b64_candidates, best_mutex)

    return result


# ═══════════════════════════════════════════════════════════════════════════
# Output formatting
# ═══════════════════════════════════════════════════════════════════════════

def print_result(result: dict, verbose: bool = False) -> None:
    print(BANNER)

    print(f"  File    : {result['filepath']}")
    print(f"  SHA-256 : {result['sha256']}")
    print()

    if result.get("warnings"):
        for w in result["warnings"]:
            print(f"  {C_WARN}[!] {w}{C_RESET}")
        print()

    if not result["success"]:
        print(f"  {C_ERR}[✗] Extraction failed: {result['error']}{C_RESET}")
        return

    print(f"  {C_OK}[✓] Configuration extracted successfully{C_RESET}")
    print()

    # Config table
    cfg   = result["config"]
    width = max(len(k) for k in cfg) if cfg else 8
    print(f"  {C_HEAD}{'Field':<{width}}   Value{C_RESET}")
    print(f"  {'─' * width}   {'─' * 40}")
    for field, value in cfg.items():
        marker = f"{C_ERR}*{C_RESET}" if field in ("Host", "Port") else " "
        print(f"  {marker}{field:<{width}}   {value}")
    print()

    c2_host = cfg.get("Host", "")
    c2_port = cfg.get("Port", "")
    if c2_host and c2_port:
        print(f"  {C_WARN}C2 endpoint : {c2_host}:{c2_port}{C_RESET}")
        print()

    if verbose and "all_strings" in result:
        print(f"  {C_HEAD}── All #US stream strings ({len(result['all_strings'])} total) ──{C_RESET}")
        for s in result["all_strings"]:
            tag = "[B64]" if is_base64_candidate(s) else "[STR]"
            print(f"    {tag}  {s!r}")
        print()

        if "b64_candidates" in result:
            print(f"  {C_HEAD}── Base64 candidates ({len(result['b64_candidates'])}) ──{C_RESET}")
            for s in result["b64_candidates"]:
                print(f"    {s}")
            print()

        if "mutex_candidates" in result:
            print(f"  {C_HEAD}── Mutex candidates ({len(result['mutex_candidates'])}) ──{C_RESET}")
            for s in result["mutex_candidates"]:
                marker = " [SELECTED]" if s == result.get("mutex") else ""
                print(f"    {s!r}{marker}")
            print()


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="XWorm V3.x static config extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage")[1] if "Usage" in __doc__ else "",
    )
    parser.add_argument("sample",
                        help="Path to the XWorm sample (.exe)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all #US strings and candidate classification")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output results as JSON instead of a table")
    parser.add_argument("-o", "--out",
                        help="Write JSON output to this file (implies --json)")
    args = parser.parse_args()

    if not Path(args.sample).is_file():
        print(f"[!] File not found: {args.sample}", file=sys.stderr)
        sys.exit(1)

    result = extract_config(args.sample, verbose=args.verbose)

    if args.json or args.out:
        # Remove non-serialisable verbose fields if present
        out = {k: v for k, v in result.items()}
        text = json.dumps(out, indent=2)
        if args.out:
            Path(args.out).write_text(text)
            print(f"[+] JSON written to {args.out}")
        else:
            print(text)
    else:
        print_result(result, verbose=args.verbose)

    sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
