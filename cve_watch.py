#!/usr/bin/env python3
import os, json, argparse, requests, datetime, re, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
UTC = datetime.timezone.utc
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200
MAX_LEN = 1800

POC_RE = re.compile(
    r"\b(proof[- ]?of[- ]?concept|\bpoc\b|exploit code|public exploit|metasploit|exploit[- ]?db|github\.com)\b",
    re.I
)

def load_env():
    for p in (".env", "../.env"):
        fp = os.path.join(BASE_DIR, p)
        if os.path.exists(fp):
            for line in open(fp):
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    os.environ.setdefault(k, v.strip('"'))

load_env()
NVD_KEY = os.getenv("NVD_API_KEY")
WEBHOOK = os.getenv("DISCORD_WEBHOOK_CVES") or os.getenv("DISCORD_WEBHOOK_URL")

def load_state():
    try:
        return json.load(open(STATE_FILE))
    except:
        return {"sent": {}}

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    json.dump(state, open(tmp, "w"), indent=2)
    os.replace(tmp, STATE_FILE)

def fetch_all(params):
    start = 0
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    while True:
        p = dict(params, resultsPerPage=PAGE_SIZE, startIndex=start)
        r = requests.get(NVD_URL, params=p, headers=headers, timeout=30)
        if r.status_code != 200:
            return
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return
        for v in vulns:
            yield v
        start += PAGE_SIZE
        if start >= data.get("totalResults", 0):
            return

def cvss_ok(metrics, min_s, no_auth):
    for m in metrics:
        d = m.get("cvssData", {})
        s = d.get("baseScore", 0)
        v = d.get("vectorString", "")
        if s >= min_s and "AV:N" in v and (not no_auth or "PR:N" in v):
            return s, v
    return None, None

def send_chunks(text):
    if not WEBHOOK:
        return
    buf = ""
    for line in text.split("\n"):
        if len(buf) + len(line) + 1 > MAX_LEN:
            requests.post(WEBHOOK, json={"content": buf})
            time.sleep(1)
            buf = line
        else:
            buf += ("\n" if buf else "") + line
    if buf:
        requests.post(WEBHOOK, json={"content": buf})

ap = argparse.ArgumentParser()
ap.add_argument("-window", type=int, default=12)
ap.add_argument("-min", type=float, default=5.0)
ap.add_argument("-no-auth", action="store_true")
ap.add_argument("-poc", action="store_true")
ap.add_argument("-why", action="store_true")
ap.add_argument("--digest", action="store_true")
ap.add_argument("-dry-run", action="store_true")
args = ap.parse_args()

now = datetime.datetime.now(UTC)
state = load_state()
sent = state.setdefault("sent", {})

params = {
    "lastModStartDate": (now - datetime.timedelta(hours=args.window)).isoformat(),
    "lastModEndDate": now.isoformat()
}

digest_blocks = []
alerts = []

for item in fetch_all(params):
    c = item.get("cve", {})
    cid = c.get("id")
    if not cid:
        continue

    metrics = []
    for k in ("cvssMetricV31", "cvssMetricV30"):
        metrics += c.get("metrics", {}).get(k, [])

    score, vector = cvss_ok(metrics, args.min, args.no_auth)
    if not score:
        continue

    desc = c.get("descriptions", [{}])[0].get("value", "")
    has_poc = bool(POC_RE.search(desc))
    prev = sent.get(cid)

    if args.digest:
        block = (
            f"🚨 **{cid}**\n"
            f"CVSS: {score} ({vector})\n"
            f"{desc}\n"
            f"https://nvd.nist.gov/vuln/detail/{cid}"
        )
        digest_blocks.append(block)
        continue

    why = []
    if not prev:
        why.append("New CVE")
    elif args.poc and not prev.get("had_poc") and has_poc:
        why.append("PoC added")
    else:
        continue

    if args.why:
        if score >= 9:
            why.append("Critical severity")
        elif score >= 7:
            why.append("High severity")
        if "AV:N" in vector and "PR:N" in vector:
            why.append("Remote unauthenticated")

    sent[cid] = {
        "first_seen": prev.get("first_seen", now.isoformat()) if prev else now.isoformat(),
        "had_poc": has_poc,
        "cvss": score,
        "vector": vector
    }

    msg = f"🚨 **{cid}**\nCVSS: {score} ({vector})"
    if args.why and why:
        msg += "\nWHY:\n- " + "\n- ".join(why)
    msg += f"\n{desc}\nhttps://nvd.nist.gov/vuln/detail/{cid}"
    alerts.append(msg)

out = []
if args.digest and digest_blocks:
    out.append(f"🗞️ **CVE Digest (last {args.window}h)**")
    out.extend(digest_blocks)
elif alerts:
    out.extend(alerts)

final = "\n".join(out)
print(final)
if not args.dry_run and final:
    send_chunks(final)

save_state(state)
