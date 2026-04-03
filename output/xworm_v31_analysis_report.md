# XWorm V3.1 — Static Configuration Extraction & Scalable Detection

## Overview

**XWorm** is a widely used Remote Access Trojan (RAT) that has been actively observed in campaigns since at least 2022. It is commonly distributed through phishing emails and multi-stage loaders, and is frequently sold or shared in underground forums, making it accessible to a broad range of threat actors.

Written in VB.NET, XWorm provides operators with a full set of remote control capabilities:

- Remote command execution  
- Keylogging and activity monitoring  
- Webcam and screen capture  
- File management and plugin execution  
- DDoS functionality  

XWorm infections have been observed across a wide range of targets, including small businesses and enterprise environments. Once deployed, it provides attackers with full remote access to the infected system, enabling data theft, surveillance, and further payload delivery.
---

## Key Observation

Across multiple samples, XWorm V3.x exhibits a consistent pattern:

> The malware stores its Command & Control (C2) configuration as **encrypted Base64 strings inside the `.NET #US metadata stream`**

This approach:

- Hides configuration from basic string analysis  
- Avoids obvious plaintext indicators  
- Remains fully reversible through static analysis  

---

## Objective

This analysis demonstrates how to:

- Identify a XWorm sample and confirm its family  
- Locate encrypted configuration data within .NET metadata  
- Reverse the encryption routine used by the malware  
- Extract the full C2 configuration without executing the binary  
- Scale the approach using automated tooling  

The methodology is validated against a dataset of:

> **100+ XWorm V3.x samples**, confirming that the technique generalizes across multiple campaigns.

---

## Static Analysis

### Sample Overview & Identification

The sample analyzed in this report:

| Property | Value |
|---|---|
| SHA256 | `cdde3b2650c951e774a8694208c0d151e91b40db5d21da3d790d88ebd702edec` |
| Internal Name | `XClient.exe` |
| File Type | .NET PE (VB.NET) |
| Compile Time | 2026-04-01 |
| Family | XWorm (v3.x) |

<p align="center">
  <img src="../images/malcat_fileidentification.png" width="700">
</p>
<p align="center"><em>Figure 1 — File identification and hash verification</em></p>

Initial triage confirms that the binary is a **.NET assembly compiled in VB.NET**, a common choice for commodity malware due to rapid development and compatibility with obfuscation frameworks.

---

### Family Identification

Using Detect-It-Easy (`diec`), the sample is classified as:

```json
"Malware: XWorm(3.0-5.0)"
