# XWorm V3.x Config Extractor + YARA Detection

Static analysis tools for **XWorm V3.x** — a VB.NET RAT that stores its C2
configuration encrypted inside the `.NET #US` metadata stream.

The YARA rule tells you whether the extractor will work **before you run it**.

## Files

| File | Purpose |
|---|---|
| `xworm_extractor.py` | Decrypts and prints the C2 configuration |
| `xworm_v3x_extractor_compatible.yar` | Detects samples the extractor can handle |

## Quick start

```bash
# Step 1 — check if the extractor will work on your sample
yara xworm_v3x_extractor_compatible.yar <sample.exe>

# Step 2 — if the rule matched, extract the config
python3 xworm_extractor.py <sample.exe>
```

If the YARA rule produces **no output**, the extractor will not work on that
sample (see [Limitations](#limitations)).

## YARA rule

**File:** `xworm_v3x_extractor_compatible.yar`

Contains two rules:

### `XWorm_V3x_Extractor_Compatible` — use this one

Matches any unobfuscated XWorm V3.x sample that uses the AES-256-ECB / MD5
encryption scheme the extractor targets. A match means the extractor is
expected to recover the full config.

**What it looks for:**

| String | Where in binary | Why |
|---|---|---|
| `BSJB` | Binary marker | Confirms .NET assembly |
| `AlgorithmAES` | `.NET #Strings stream` | The exact decryptor class — unique to XWorm |
| `RijndaelManaged` | `.NET #Strings stream` | AES implementation used |
| `MD5CryptoServiceProvider` | `.NET #Strings stream` | Key derivation primitive |
| `USBNM` | `.NET #Strings stream` | Settings class field — confirms the config structure |
| `ClientSocket` | `.NET #Strings stream` | C2 communication class |
| `XWorm V3` + commands | `.NET #US stream (UTF-16LE)` | Runtime strings — version + C2 commands |

### `XWorm_V31_Exact_Build` — supplement only

Matches the exact V3.1 build variant using the hardcoded version string
(`XWorm V3.1`), assembly name (`XClient`), and builder GUID. Useful for
pivoting on a sample corpus. **Do not use this rule alone** to decide whether
to run the extractor — use the main rule for that.

## Config extractor

**File:** `xworm_extractor.py`

**Requires:** Python 3.10+ and the `cryptography` package.

```bash
pip install cryptography
```

### How it works

1. Parses the `.NET #US` metadata stream directly from the PE binary — no
   external tools needed.
2. Classifies strings as encrypted (Base64) or plaintext (Mutex candidates).
3. Derives the AES-256-ECB key for each Mutex candidate using XWorm's scheme:
   ```
   md5        = MD5( UTF-8(Mutex) )
   key[0:16]  = md5
   key[15:31] = md5        # overlapping Array.Copy at offset 15
   key[31]    = 0x00
   ```
4. Decrypts all Base64 values and validates the output as printable UTF-8.
5. Maps decrypted values to field names: `Host`, `Port`, `KEY`, `SPL`, `USBNM`.

### Usage

```bash
# Human-readable table
python3 xworm_extractor.py sample.exe

# JSON output
python3 xworm_extractor.py sample.exe --json

# Save JSON to file
python3 xworm_extractor.py sample.exe --out result.json

# Show all #US strings and candidate classification
python3 xworm_extractor.py sample.exe --verbose
```

### Example output

```
  ╔══════════════════════════════════════════════════╗
  ║      XWorm V3.x Configuration Extractor          ║
  ║      Method : static / .NET #US stream parsing   ║
  ╚══════════════════════════════════════════════════╝

  File    : sample.exe
  SHA-256 : cdde3b2650c951e774a8694208c0d151e91b40db5d21da3d790d88ebd702edec

  [✓] Configuration extracted successfully

  Field   Value
  ─────   ────────────────────────────────────────
   Mutex   5qjCFbbcx5iGc65S
  *Host    8.tcp.cpolar.top
  *Port    14509
   KEY     <123456789>
   SPL     <Xwormmm>
   USBNM   USB.exe

  C2 endpoint : 8.tcp.cpolar.top:14509
```

---

## Limitations

Both tools share the same constraints:

| Condition | Behaviour |
|---|---|
| **XWorm V5+ / V6+** — different cipher or KDF | YARA rule will not match; extractor will fail with a clear error |
| **Obfuscated build** (ConfuserEx, .NET Reactor) | YARA rule will not match; `#Strings` / `#US` streams are empty or encrypted |
| **Mutex looks like Base64** | Extractor brute-forces all candidates and picks the highest-scoring one |
| **`cryptography` package missing** | Extractor fails immediately with install instructions |

> The YARA rule is the gate: if it does not match, do not expect the
> extractor to succeed.

## Tested on

| SHA-256 | Family | Version | Result |
|---|---|---|---|
| `cdde3b26...edec` | XWorm | V3.1 | Full config recovered |

## References

- [XWorm analysis report](output/xworm_v31_analysis_report.md)
