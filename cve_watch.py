#!/usr/bin/env python3
import os, sys, json, argparse, requests, datetime, re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", ".env"))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UTC = datetime.timezone.utc

def load_env():
    if os.path.exists(ENV_PATH):
        for line in open(ENV_PATH):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ[k] = v.strip().strip('"')

load_env()

WEBHOOK = os.getenv("DISCORD_WEBHOOK_CVES") or os.getenv("DISCORD_WEBHOOK_URL")

def utcnow():
    return datetime.datetime.now(UTC)

def load_state(ttl):
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        data = json.load(open(STATE_FILE))
        cutoff = utcnow() - datetime.timedelta(hours=ttl)
        return {k:v for k,v in data.items() if datetime.datetime.fromisoformat(v) > cutoff}
    except Exception:
        return {}

def save_state(state):
    json.dump(state, open(STATE_FILE, "w"))

def has_poc(text):
    return bool(re.search(r"exploit|poc|proof of concept|rce|ssrf|deserializ", text, re.I))

def match_tags(text, tags):
    return any(t in text.lower() for t in tags)

ap = argparse.ArgumentParser(description="High-signal CVE watcher")
ap.add_argument("-min", type=float, default=9.0)
ap.add_argument("-max", type=float, default=10.0)
ap.add_argument("-window", type=int, default=48)
ap.add_argument("-no-auth", action="store_true")
ap.add_argument("-no-ui", action="store_true")
ap.add_argument("-tags")
ap.add_argument("-poc", action="store_true")
ap.add_argument("-state", type=int, default=2)
ap.add_argument("-clear-state", action="store_true")
ap.add_argument("-send-test", action="store_true")
ap.add_argument("-dry-run", action="store_true")
ap.add_argument("-debug", action="store_true")
args = ap.parse_args()

if args.clear_state:
    save_state({})
    print("✅ State cleared")
    sys.exit(0)

if args.send_test:
    if not WEBHOOK:
        print("❌ DISCORD webhook missing")
        sys.exit(1)
    requests.post(WEBHOOK, json={"content":"🧪 CVEWatch test message"})
    print("✅ Test message sent")
    sys.exit(0)

end = utcnow()
start = end - datetime.timedelta(hours=args.window)

params = {
    "lastModStartDate": start.isoformat(),
    "lastModEndDate": end.isoformat(),
    "resultsPerPage": 2000
}

resp = requests.get(NVD_URL, params=params, timeout=30)
resp.raise_for_status()
items = resp.json().get("vulnerabilities", [])

state = load_state(args.state)
tags = [t.strip().lower() for t in args.tags.split(",")] if args.tags else []

out = []
new_state = dict(state)

for v in items:
    cve = v.get("cve", {})
    cid = cve.get("id")
    desc = cve.get("descriptions",[{}])[0].get("value","")
    metrics = cve.get("metrics",{}).get("cvssMetricV31",[]) + cve.get("metrics",{}).get("cvssMetricV30",[])

    if cid in state:
        continue

    ok = False
    score = 0
    vector = ""

    for m in metrics:
        data = m.get("cvssData",{})
        score = data.get("baseScore",0)
        vector = data.get("vectorString","")
        if score < args.min or score > args.max:
            continue
        if "AV:N" not in vector:
            continue
        if args.no_auth and "PR:N" not in vector:
            continue
        if args.no_ui and "UI:N" not in vector:
            continue
        ok = True
        break

    if not ok:
        continue

    text = desc.lower()
    if args.poc and not has_poc(text):
        continue
    if tags and not match_tags(text, tags):
        continue

    sev = "🔥 CRITICAL" if score >= 9 else "⚠️ HIGH"
    msg = f"""{sev} **{cid}** (CVSS {score})
{desc}
https://nvd.nist.gov/vuln/detail/{cid}
"""
    out.append(msg)
    new_state[cid] = utcnow().isoformat()

if out and not args.dry_run and WEBHOOK:
    for m in out:
        requests.post(WEBHOOK, json={"content": m})

save_state(new_state)

print(f"CVE Update — {len(out)} CVEs (CVSS {args.min}–{args.max})")
