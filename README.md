# cvewatch

**High-signal CVE monitoring for bug bounty hunters and pentesters**

`cvewatch` is a lightweight CLI tool that monitors the NVD for **new or recently modified CVEs** and filters them down to **actually exploitable, bug-bounty-relevant vulnerabilities**, then sends alerts to Discord.

This tool is intentionally opinionated: it favors **remote, unauthenticated, low-interaction bugs** (SSRF, deserialization, uploads, APIs, proxies, etc.) over noisy or theoretical issues.

---

## Why cvewatch exists

Most CVE feeds are:
- extremely noisy
- full of local / physical / low-impact bugs
- not aligned with real-world web exploitation
- hard to automate meaningfully

`cvewatch` is built for:
- bug bounty hunters
- web / API pentesters
- cloud & identity researchers

It answers one question well:

> **“What CVEs changed recently that I might actually exploit?”**

---

## What cvewatch does (important)

- Queries the **NVD CVE API**
- **ONLY returns CVEs that are new or modified within the last 48 hours**
  - configurable via `-window`
- Filters by:
  - CVSS score
  - Network exploitable only (**AV:N**) — always required
  - Optional no authentication (**PR:N**)
  - Optional no user interaction (**UI:N**)
  - Optional PoC / exploit-style language
  - Optional keyword tags
- De-duplicates alerts using a local state file (TTL-based)
- Sends alerts to Discord
- Designed to run unattended via **systemd timers**

---

## Installation

### Requirements
- Python 3.10+
- `requests`
- Linux (recommended for systemd automation)

### Clone
```bash
git clone https://github.com/spencer5cent/cvewatch.git
cd cvewatch
```

### Install dependency
```bash
pip3 install requests
```

---

## Configuration

Create a `.env` file **one directory above** `cve_watch.py`:

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/XXXX/YYYY
```

> ⚠️ Never commit `.env`  
> Use `.env.example` as a template.

---

## Optional: create a shell alias

This allows you to run `cvewatch` from anywhere.

```bash
echo "alias cvewatch='python3 /path/to/cvewatch/cve_watch.py'" >> ~/.bashrc
source ~/.bashrc
```

Example:
```bash
cvewatch -min 8.5 -no-auth -no-ui -tags ssrf
```

---

## Usage

Basic example:
```bash
cvewatch -min 7 -no-auth -no-ui -tags web
```

Send a test Discord message:
```bash
cvewatch -send-test
```

Clear deduplication state:
```bash
cvewatch -clear-state
```

---

## Year filtering (`-year`)

**Default behavior:**  
If no `-year` flag is provided, `cvewatch` only includes:

> **CVE years 2018 → present**

You can override this using the `-year` flag.

### Supported formats

Single year:
```bash
-year 2020
```

Multiple years:
```bash
-year 2016,2020
```

Ranges:
```bash
-year 2020-2022
```

Mixed:
```bash
-year 2021,2010-2012
```

Example:
```bash
cvewatch -year 2019-2021 -poc -tags upload
```

---

## Flags & Options

```
-min <score>        Minimum CVSS score (default: 9.0)
-max <score>        Maximum CVSS score (default: 10.0)
-window <hours>     Lookback window for modified CVEs (default: 48)

-no-auth            Require no authentication (PR:N)
-no-ui              Require no user interaction (UI:N)
-poc                Require exploit / PoC-style language

-tags <list>        Comma-separated keyword tags
                    Example: web,ssrf,api,upload

-year <spec>        CVE year filter
                    Examples:
                      2020
                      2016,2020
                      2020-2022
                    Default: 2018 → present

-state <hours>      State TTL to suppress repeat alerts (default: 2)
-clear-state        Clear stored CVE state only
-send-test          Send a Discord test message
-dry-run            Print output without sending to Discord
-debug              Verbose debug output
```

---

## Example Output

Command:
```bash
cvewatch -min 5 -poc -no-auth -no-ui -tags web
```

Output:
```
🚨 **CVE-2026-1065** (CVSS 7.2)
The Form Maker by 10Web plugin for WordPress is vulnerable to Stored Cross-Site Scripting...
https://nvd.nist.gov/vuln/detail/CVE-2026-1065

🚨 **CVE-2026-24992** (CVSS 5.3)
Insertion of Sensitive Information Into Sent Data vulnerability in WPFactory Advanced WooCommerce Product Sales Reporting...
https://nvd.nist.gov/vuln/detail/CVE-2026-24992

🚨 **CVE-2026-25223** (CVSS 7.5)
Fastify validation bypass via malformed Content-Type header...
https://nvd.nist.gov/vuln/detail/CVE-2026-25223
```

📸 **Discord alert screenshots**
![discord](https://github.com/user-attachments/assets/a26c9b8c-91d4-42ef-9c66-276d17c26709)




---

## Automation (systemd)

`cvewatch` is designed to run unattended using **systemd timers**.

Typical setups:
- Hourly high-severity monitoring
- Twice-daily broader scans

Example commands:
```bash
cvewatch -min 8.5 -poc -no-auth -no-ui -tags web
cvewatch -min 5 -poc -no-auth -no-ui -tags web
```

---

## License

MIT
