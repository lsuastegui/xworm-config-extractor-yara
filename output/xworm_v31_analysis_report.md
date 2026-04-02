## Introduction

**XWorm** is a commodity **Remote Access Trojan (RAT)** written in VB.NET that has been actively used in commodity malware campaigns since at least 2022. It provides typical RAT capabilities such as:

- Remote command execution
- Keylogging
- Webcam capture
- File management
- DDoS functionality

Public reporting and community rules (e.g., SEKOIA YARA signatures) classify XWorm as a widely distributed commodity RAT, often delivered via phishing campaigns and loaders.

Additionally, this research was validated against a dataset of **100+ XWorm V3.x samples** collected from multiple sources.

Each sample was processed using the extractor, and the resulting configurations were analyzed to identify consistent patterns across campaigns.

This allowed not only to confirm the reliability of the extraction method, but also to derive a set of **real-world Indicators of Compromise (IOCs)** at scale.
