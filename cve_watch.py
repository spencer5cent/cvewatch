#!/usr/bin/env python3
import os, sys, json, argparse, requests, datetime, re, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_CANDIDATES = [
    os.path.join(BASE_DIR, ".env"),
    os.path.join(BASE_DIR, "..", ".env"),
]
STATE_FILE = os.path.join(BASE_DIR, "state.json")
UTC = datetime.timezone.utc
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

POC_RE = re.compile(r"exploit|poc|proof[- ]?of[- ]?concept|bypass|rce|upload", re.I)

def load_env():
    for path in ENV_CANDIDATES:
        if os.path.exists(path):
            for line in open(path):
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v.strip().strip('"'))

load_env()

NVD_KEY = os.getenv("NVD_API_KEY")
WEBHOOK = os.getenv("DISCORD_WEBHOOK_CVES") or os.getenv("DISCORD_WEBHOOK_URL")

def utcnow():
    return datetime.datetime.now(UTC)

def load_state():
    if not os.path.exists(STATE_FILE):
        return {"sent": {}}
    try:
        return json.load(open(STATE_FILE))
    except Exception:
        return {"sent": {}}

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    json.dump(state, open(tmp, "w"), indent=2)
    os.replace(tmp, STATE_FILE)

def fetch_nvd(params):
    headers = {}
    if NVD_KEY:
        headers["apiKey"] = NVD_KEY
    r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
    if r.status_code != 200 or not r.text.strip():
        return None
    return r.json()

def cvss_ok(metrics, min_s, no_auth):
    for m in metrics:
        cvss = m.get("cvssData", {})
        score = cvss.get("baseScore", 0)
        vector = cvss.get("vectorString", "")
        if score < min_s:
            continue
        if "AV:N" not in vector:
            continue
        if no_auth and "PR:N" not in vector:
            continue
        return score, vector
    return None, None

ap = argparse.ArgumentParser()
ap.add_argument("-min", type=float, default=5.0)
ap.add_argument("-window", type=int, default=48)
ap.add_argument("-no-auth", action="store_true")
ap.add_argument("-poc", action="store_true")
ap.add_argument("-why", action="store_true")
ap.add_argument("-new-only", action="store_true")
ap.add_argument("-fill-state", action="store_true")
ap.add_argument("-dry-run", action="store_true")
args = ap.parse_args()

state = load_state()
sent = state.setdefault("sent", {})
now = utcnow()

def process_window(hours, publish_only):
    params = {"resultsPerPage": 200}
    key = "pubStartDate" if publish_only else "lastModStartDate"
    params[key] = (now - datetime.timedelta(hours=hours)).isoformat()
    params[key.replace("Start", "End")] = now.isoformat()

    data = fetch_nvd(params)
    if not data:
        return 0

    added = 0
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid or not cid.startswith("CVE-"):
            continue

        metrics = []
        for k in ("cvssMetricV31", "cvssMetricV30"):
            metrics += cve.get("metrics", {}).get(k, [])

        score, vector = cvss_ok(metrics, args.min, args.no_auth)
        if not score:
            continue

        desc = cve.get("descriptions", [{}])[0].get("value", "")
        has_poc = bool(POC_RE.search(desc))

        prev = sent.get(cid)
        if prev:
            if not prev.get("had_poc") and has_poc:
                why = "POC_ADDED"
            else:
                continue
        else:
            why = "NEW"

        sent[cid] = {
            "first_seen": prev.get("first_seen", now.isoformat()) if prev else now.isoformat(),
            "had_poc": has_poc,
            "cvss": score,
            "vector": vector
        }

        if not args.fill_state:
            msg = f"🚨 **{cid}**\nCVSS: {score} ({vector})"
            if args.why:
                msg += f"\nWHY: {why}"
            msg += f"\n{desc}\nhttps://nvd.nist.gov/vuln/detail/{cid}"
            print(msg)
            if WEBHOOK and not args.dry_run:
                requests.post(WEBHOOK, json={"content": msg})

        added += 1

    return added

if args.fill_state:
    for h in (8760, 6000, 4000, 2000, 1000, 500, 250):
        process_window(h, False)
        save_state(state)
        time.sleep(90)
    sys.exit(0)

process_window(args.window, args.new_only)
save_state(state)
