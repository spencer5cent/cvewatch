# cvewatch

**High-signal CVE monitoring for bug bounty hunters and pentesters**

`cvewatch` is a lightweight CLI tool that continuously monitors the NVD for **new or recently updated CVEs** and filters them down to **actually exploitable, bug-bounty-relevant vulnerabilities** — then sends alerts to Discord.

This tool is opinionated by design: it favors **remote, unauthenticated, low-interaction bugs** (SSRF, deserialization, uploads, APIs, proxies, etc.) over noisy or low-impact issues.

---

## Why cvewatch exists

Most CVE feeds are:
- too noisy
- too late
- full of local / physical / theoretical bugs
- not aligned with real-world web exploitation

`cvewatch` is built for:
- bug bounty hunters
- web app pentesters
- cloud / API / identity researchers

It answers:
> “What CVEs dropped *recently* that I might actually exploit?”

---

## What it does

- Queries NVD CVE API on a rolling time window
- Filters by **CVSS score**
- Requires **AV:N (network exploitable)** by default
- Optional filters for:
  - No auth (PR:N)
  - No user interaction (UI:N)
  - PoC-like language
  - Keyword / tag matching
- De-duplicates results using a local state file
- Sends alerts to Discord
- Designed to be run via **systemd timers**

---

## Installation

### Requirements
- Python 3.10+
- `requests` library
- Linux (recommended for systemd usage)

### Clone the repo
```bash
git clone https://github.com/spencer5cent/cvewatch.git
cd cvewatch
