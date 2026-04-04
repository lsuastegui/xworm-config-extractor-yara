# XWorm Config Extractor + YARA Compatibility Detection

Static analysis tools for **XWorm**, a VB.NET-based RAT that stores its C2 configuration encrypted inside the `.NET #US` metadata stream. It supports multiple XWorm versions (observed across V3–V7), leveraging the consistent configuration format and encryption scheme used across variants.

The YARA rule determines whether a sample implements the configuration scheme required by the extractor before execution.

## Files

| File | Purpose |
|---|---|
| `xworm_extractor.py` | Decrypts and prints the C2 configuration |
| `xworm_extractor_compatible.yar` | Detects samples the extractor can handle |

## Quick start

```bash
# Step 1 — check if the extractor will work on your sample
yara xworm_extractor_compatible.yar <sample.exe>

# Step 2 — if the rule matched, extract the config
python3 xworm_extractor.py <sample.exe>
```

If the YARA rule produces **no output**, the extractor will not work on that
sample (see [Limitations](#limitations)).

## YARA rule

**File:** `xworm_extractor_compatible.yar`

Contains two rules:

### `XWorm_Extractor_Compatible` — use this one

Matches any unobfuscated XWorm sample that implements the configuration
storage and AES-256-ECB / MD5 encryption scheme targeted by the extractor. A match means the extractor is
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
| `XWorm version strings` + commands | `.NET #US stream (UTF-16LE)` | Runtime strings — version + C2 commands |

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

This approach enables fully static extraction without executing the sample:

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
  ║      XWorm Configuration Extractor               ║
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
| **Modified encryption scheme** (custom builds or future variants) | YARA rule will not match; extractor may fail |
| **Obfuscated build** (ConfuserEx, .NET Reactor) | YARA rule will not match; `#Strings` / `#US` streams may be encrypted or altered |
| **Non-standard configuration format** | Extractor may fail to correctly map fields |
| **Mutex looks like Base64** | Extractor brute-forces candidates and selects the highest-scoring result |
| **`cryptography` package missing** | Extractor fails immediately with install instructions |

> The YARA rule acts as a compatibility gate: if it does not match, the extractor is not expected to succeed.

## References

- [XWorm analysis report](output/xworm_analysis_report.md)
