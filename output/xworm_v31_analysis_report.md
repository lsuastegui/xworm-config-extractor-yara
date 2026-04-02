# XWorm V3.1 — Static Configuration Extraction & Scalable Detection

## Overview

Remote Access Trojans (RATs) continue to dominate real-world intrusion activity, largely due to their accessibility and modular design. Among them, **XWorm** has emerged as a widely adopted tool in low-to-mid sophistication campaigns, offering a rich feature set through a simple builder interface.

Written in VB.NET, XWorm provides operators with capabilities such as:

- Remote command execution  
- Keylogging and user activity monitoring  
- Webcam and screen capture  
- File management and plugin-based extensibility  
- Distributed denial-of-service (DDoS) functionality  

Public reporting and community detection rules (including those from :contentReference[oaicite:1]{index=1}) consistently identify XWorm as a **commodity RAT actively used in the wild**, often distributed via phishing or commodity loaders.

---

## Key Observation

During analysis of multiple XWorm samples, a recurring pattern emerges:

> The malware stores its Command & Control (C2) configuration as **encrypted strings inside the `.NET #US metadata stream`**

Unlike many commodity RATs that rely on plaintext or resource-based storage, this approach:

- Obscures configuration from basic string analysis  
- Avoids obvious indicators in the binary  
- Still remains **fully reversible via static analysis**  

This design makes XWorm V3.x an ideal target for **repeatable configuration extraction at scale**.

---

## Objective

This report focuses on a **XWorm V3.1 sample** and demonstrates how to:

- Identify the malware and confirm its family  
- Locate the encrypted configuration within .NET metadata  
- Reverse the encryption routine used by the malware  
- Extract the full C2 configuration without execution  
- Scale the process using automated tooling  

In addition, the methodology is validated against a dataset of:

> **100+ XWorm V3.x samples**, confirming that the extraction technique generalizes across multiple campaigns.

---

## Analytical Approach

The analysis follows a structured workflow designed for reproducibility:
