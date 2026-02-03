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

- Queries the NVD CVE API on a rolling time window
- Filters by **CVSS score**
- Requires **AV:N (network exploitable)** by default
- Optional filters for:
  - No authentication required (PR:N)
  - No user interaction required (UI:N)
  - PoC / exploit-style language
  - Keyword / tag matching
- De-duplicates alerts using a local state file with TTL
- Sends alerts to Discord
- Designed to run unattended via **systemd timers**

---

## Installation

### Requirements
- Python 3.10+
- `requests` library
- Linux (recommended for systemd usage)

### Clone the repository
```bash
git clone https://github.com/spencer5cent/cvewatch.git
cd cvewatch
```

### Install dependencies
```bash
pip3 install requests
```

---

## Configuration

Create a `.env` file **one directory above** `cve_watch.py`:

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/XXXX/YYYY
```


---

## Usage

Basic example:
```bash
python3 cve_watch.py -min 7 -no-auth -no-ui -tags web
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

## Flags & Options

```
-min <score>        Minimum CVSS score (default: 9.0)
-max <score>        Maximum CVSS score (default: 10.0)
-window <hours>     Lookback window in hours (default: 48)

-no-auth            Require no authentication (PR:N)
-no-ui              Require no user interaction (UI:N)
-poc                Require exploit / PoC-style language

-tags <list>        Comma-separated keyword tags
                    Example: web,ssrf,api,upload

-state <hours>      State TTL in hours (default: 2)
-clear-state        Clear stored CVE state only
-send-test          Send a Discord test message
-dry-run            Print output without sending
-debug              Verbose debug output
```

---

## Tags

Tags are **keyword-based**, not strict categories. They help reduce noise.

Recommended high-signal tags:
- ssrf
- proxy
- api
- upload
- deserialization
- graphql
- gateway
- oauth
- jwt

Example:
```bash
cvewatch -min 8 -no-auth -no-ui -tags ssrf,api
```

---

## Automation (systemd Timers)

`cvewatch` is designed to run unattended using **systemd timers**.

### Hourly high-signal check
```bash
cvewatch -min 8.5 -poc -no-auth -no-ui -tags web
```

### Twice-daily broad check
```bash
cvewatch -min 5 -poc -no-auth -no-ui -tags web -send-test
```


### systemd setup (recommended)

Create two services and two timers.

---

#### Hourly high-signal scan (CVSS ≥ 8.5)

Create `/etc/systemd/system/cvewatch-hourly.service`:
```
[Unit]
Description=CVEWatch Hourly High-Signal Scan

[Service]
Type=oneshot
WorkingDirectory=/path/to/cvewatch
ExecStart=/usr/bin/python3 /path/to/cvewatch/cve_watch.py -min 8.5 -poc -no-auth -no-ui -tags web
```

Create `/etc/systemd/system/cvewatch-hourly.timer`:
```
[Unit]
Description=CVEWatch Hourly Timer

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

---

#### Twice-daily broader scan (CVSS ≥ 5)

Create `/etc/systemd/system/cvewatch-daily.service`:
```
[Unit]
Description=CVEWatch Twice Daily Broad Scan

[Service]
Type=oneshot
WorkingDirectory=/path/to/cvewatch
ExecStart=/usr/bin/python3 /path/to/cvewatch/cve_watch.py -min 5 -poc -no-auth -no-ui -tags web
```

Create `/etc/systemd/system/cvewatch-daily.timer`:
```
[Unit]
Description=CVEWatch Twice Daily Timer

[Timer]
OnCalendar=*-*-* 10:30:00
OnCalendar=*-*-* 18:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

---

Enable and start timers:
```
sudo systemctl daemon-reload
sudo systemctl enable --now cvewatch-hourly.timer cvewatch-daily.timer
```

Verify:
```
systemctl list-timers | grep cvewatch
```

> 💡 Use `-send-test` once manually to confirm Discord delivery.

---

## License

MIT
