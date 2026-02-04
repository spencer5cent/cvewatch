#!/usr/bin/env python3
import os, sys, json, argparse, requests, datetime, re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", ".env"))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
UTC = datetime.timezone.utc
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
        return {"sent": {}, "ttl": 2}
    try:
        return json.load(open(STATE_FILE))
    except Exception:
        return {"sent": {}, "ttl": 2}

def save_state(state):
    json.dump(state, open(STATE_FILE, "w"))

def cvss_match(metrics, min_s, max_s, no_auth, no_ui):
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
        return score, vector
    return None, None

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
    json.dump({"sent": {}, "ttl": args.state}, open(STATE_FILE, "w"))
    print("✅ State cleared")
    sys.exit(0)

if args.send_test:
    if not WEBHOOK:
        print("❌ Discord webhook missing")
        sys.exit(1)
    requests.post(WEBHOOK, json={"content": "🧪 CVEWatch test message"})
    print("✅ Test message sent")
    sys.exit(0)

state = load_state()
state["ttl"] = args.state
now = utcnow()

params = {
    "pubStartDate": (now - datetime.timedelta(hours=args.window)).isoformat(),
    "pubEndDate": now.isoformat(),
    "resultsPerPage": 2000,
}

resp = requests.get(NVD_URL, params=params, timeout=30)
resp.raise_for_status()
data = resp.json()

tags = [t.strip().lower() for t in args.tags.split(",")] if args.tags else []

hits = 0

for item in data.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cid = cve.get("id")
    if not cid:
        continue

    last_sent = state["sent"].get(cid)
    if last_sent:
        sent_time = datetime.datetime.fromisoformat(last_sent)
        if (now - sent_time).total_seconds() < args.state * 3600:
            continue

    desc = " ".join(d["value"] for d in cve.get("descriptions", []))
    desc_l = desc.lower()

    if tags and not any(t in desc_l for t in tags):
        continue

    if args.poc and not re.search(r"(exploit|poc|proof|bypass|rce|ssrf|deserialize|upload)", desc_l):
        continue

    metrics = (
        cve.get("metrics", {}).get("cvssMetricV31")
        or cve.get("metrics", {}).get("cvssMetricV30")
        or []
    )

    score, vector = cvss_match(metrics, args.min, args.max, args.no_auth, args.no_ui)
    if score is None:
        continue

    msg = (
        f"🚨 **{cid}** (CVSS {score})\n"
        f"{desc[:900]}\n"
        f"https://nvd.nist.gov/vuln/detail/{cid}"
    )

    print(msg + "\n")
    hits += 1

    if WEBHOOK and not args.dry_run:
        requests.post(WEBHOOK, json={"content": msg})

    state["sent"][cid] = now.isoformat()

save_state(state)

if hits == 0:
    print("ℹ️ No matching CVEs")

