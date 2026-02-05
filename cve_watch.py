#!/usr/bin/env python3
import os, sys, json, argparse, requests, datetime, re, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", ".env"))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
UTC = datetime.timezone.utc
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


POC_RE = re.compile(r"exploit|poc|proof[- ]?of[- ]?concept|bypass|rce|upload", re.I)

def fetch_nvd_paginated(base_params, sleep_sec=2):
    all_items = []
    start = 0
    while True:
        p = dict(base_params)
        p["startIndex"] = start
        r = requests.get(NVD_URL, params=p, timeout=30)
        if r.status_code != 200 or not r.text.strip():
            break
        j = r.json()
        items = j.get("vulnerabilities", [])
        if not items:
            break
        all_items.extend(items)
        if len(items) < p.get("resultsPerPage", 200):
            break
        start += len(items)
        time.sleep(sleep_sec)
    return {"vulnerabilities": all_items}

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

def load_state():
    if not os.path.exists(STATE_FILE):
        return {"sent": {}}
    try:
        raw = json.load(open(STATE_FILE))
        sent = {}
        for k, v in raw.get("sent", {}).items():
            if isinstance(v, str):
                sent[k] = {"first_seen": v, "had_poc": False}
            else:
                sent[k] = v
        return {"sent": sent}
    except Exception:
        return {"sent": {}}

def save_state(state):
    json.dump(state, open(STATE_FILE, "w"), indent=2)

def parse_years(values):
    years = set()
    for val in values:
        for part in val.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                years.update(range(int(a), int(b) + 1))
            else:
                years.add(int(part))
    return years

def cvss_ok(metrics, min_s, max_s, no_auth, no_ui):
    for m in metrics:
        cvss = m.get("cvssData", {})
        score = cvss.get("baseScore", 0)
        vector = cvss.get("vectorString", "")
        if score < min_s or score > max_s:
            continue
        if "AV:N" not in vector:
            continue
        if no_auth and "PR:N" not in vector:
            continue
        if no_ui and "UI:N" not in vector:
            continue
        return True
    return False

def matches_tags(text, tags):
    if not tags:
        return True
    t = text.lower()
    return any(tag in t for tag in tags)

ap = argparse.ArgumentParser(description="High-signal CVE watcher")
ap.add_argument("-min", type=float, default=9.0)
ap.add_argument("-max", type=float, default=10.0)
ap.add_argument("-window", type=int, default=48)
ap.add_argument("-no-auth", action="store_true")
ap.add_argument("-no-ui", action="store_true")
ap.add_argument("-poc", action="store_true")
ap.add_argument("-tags")
ap.add_argument("-new-only", action="store_true")
ap.add_argument("-year", action="append")
ap.add_argument("-why", action="store_true")
ap.add_argument("-clear-state", action="store_true")
ap.add_argument("-send-test", action="store_true")
ap.add_argument("-dry-run", action="store_true")
ap.add_argument("-debug", action="store_true")
args = ap.parse_args()

if args.clear_state:
    save_state({"sent": {}})
    print("✅ State cleared")
    sys.exit(0)

if args.send_test:
    if not WEBHOOK:
        print("❌ Discord webhook missing")
        sys.exit(1)
    requests.post(WEBHOOK, json={"content": "🧪 CVEWatch test message"})
    print("✅ Test message sent")
    sys.exit(0)

tags = [t.strip().lower() for t in args.tags.split(",")] if args.tags else []
allowed_years = parse_years(args.year) if args.year else set(range(2010, utcnow().year + 1))


params = {"resultsPerPage": 200}
time_key = "pubStartDate" if args.new_only else "lastModStartDate"
params[time_key] = (utcnow() - datetime.timedelta(hours=args.window)).isoformat()
params[time_key.replace("Start", "End")] = utcnow().isoformat()

data = fetch_nvd_paginated(params)

state = load_state()
sent = state.get("sent", {})
now = utcnow()

for item in data.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cid = cve.get("id", "")
    if not cid.startswith("CVE-"):
        continue

    year = int(cid.split("-")[1])
    if year not in allowed_years:
        continue

    metrics = []
    for k in ("cvssMetricV31", "cvssMetricV30"):
        metrics += cve.get("metrics", {}).get(k, [])

    if not cvss_ok(metrics, args.min, args.max, args.no_auth, args.no_ui):
        continue

    desc = cve.get("descriptions", [{}])[0].get("value", "")
    has_poc = bool(POC_RE.search(desc))

    if args.poc and not has_poc:
        continue
    if not matches_tags(desc, tags):
        continue

    prev = sent.get(cid)

    why = None
    if not prev:
        why = "NEW"
    elif not prev.get("had_poc") and has_poc:
        why = "POC_ADDED"
    else:
        continue

    msg = f"🚨 **{cid}**"
    if args.why:
        msg += f"\nWHY: {why}"
    msg += f"\n{desc}\nhttps://nvd.nist.gov/vuln/detail/{cid}"

    print(msg)
    if WEBHOOK and not args.dry_run:
        requests.post(WEBHOOK, json={"content": msg})

    sent[cid] = {
        "first_seen": prev.get("first_seen", now.isoformat()) if prev else now.isoformat(),
        "had_poc": has_poc
    }

state["sent"] = sent
save_state(state)
