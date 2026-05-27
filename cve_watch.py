#!/usr/bin/env python3
"""
cve_watch.py — Web-focused CVE watcher for security researchers.

Alert logic:
  1. CVSS >= min (default 8.5), AV:N (network reachable), PR:N (no auth required)
  2. NOT excluded (kernel, firmware, Apple iOS/Android, physical-access-only, ICS/SCADA)
  3. Matches a WEB-tier product AND a web-exploitable vuln type  → [WEB] alert
     OR matches a NETWORK-tier product AND a network vuln type   → [NETWORK] alert
  4. Dedup: skip already-seen CVEs unless a PoC signal newly appeared in the description
"""
import os, sys, json, argparse, requests, datetime, re, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
UTC = datetime.timezone.utc
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_LEN = 1900  # Discord message limit with safety margin

# ── PoC detection ─────────────────────────────────────────────────────────────
POC_RE = re.compile(
    r"proof[- ]?of[- ]?concept|poc available|exploit code|actively exploit|"
    r"in the wild|public exploit|working exploit|metasploit|nuclei|exploit-db|"
    r"github\.com.*exploit",
    re.I,
)

# ── Web-tier products ─────────────────────────────────────────────────────────
# Web-tier: common externally-exposed apps and frameworks seen in real-world scopes.
WEB_PRODUCTS = [
    # Java / Spring ecosystem
    "spring boot", "spring framework", "spring security", "spring mvc",
    "spring core", "spring data", "spring cloud",
    "node.js", "nodejs",
    "fastify",
    "express.js", "expressjs",
    "graphql", "apollo server", "apollo gateway",
    "apache kafka", "kafka",
    "kubernetes", "k8s",
    "docker",
    "nginx",
    "redis",
    "memcached",
    "cassandra", "apache cassandra",
    "openstack",
    "apache pinot",
    "cloudflare",
    # Java ecosystem
    "apache tomcat", "tomcat",
    "apache struts", "struts",
    "apache solr", "solr",
    "apache airflow", "airflow",
    "apache shiro", "shiro",
    "apache log4j", "log4j", "log4shell",
    "apache activemq", "activemq",
    "apache dubbo", "dubbo",
    "apache cxf",
    "oracle weblogic", "weblogic",
    "jboss", "wildfly", "undertow",
    "glassfish",
    "ibm websphere", "websphere",
    "coldfusion",
    "grails",
    "quarkus",
    "micronaut",
    # PHP (specific named products only — bare "php" matches every obscure app)
    "php-fpm", "php fpm",           # PHP engine itself
    "phpmailer",
    "phpmyadmin",
    "laravel", "symfony", "codeigniter", "yii", "cakephp",
    "wordpress",
    "kali forms",
    "drupal",
    "joomla",
    "magento",
    "prestashop",
    "typo3",
    "moodle",
    "opencart",
    "roundcube",
    "squirrelmail",
    "dolibarr",
    # Python
    "django",
    "flask",
    "fastapi",
    "marimo",
    # Ruby
    "ruby on rails", "rails",
    # Node / JS
    "nestjs",
    "nuxt",
    "next.js", "nextjs",
    # .NET / Microsoft
    "asp.net", "aspnet",
    "microsoft exchange", "exchange server",
    "sharepoint",
    "iis",
    # Atlassian
    "jira", "confluence", "bitbucket", "atlassian",
    # DevOps / CI/CD
    "gitlab",
    "jenkins",
    "github enterprise", "github actions",
    "bamboo",
    "teamcity",
    "sonarqube",
    "nexus repository",
    "artifactory",
    "argocd", "argo cd",
    # Observability / search
    "grafana",
    "kibana", "elasticsearch", "opensearch",
    "zabbix",
    "netdata",
    # Auth / secrets
    "keycloak",
    "hashicorp vault",
    "consul",
    # Object storage / cloud-native
    "minio",
    "harbor",
    "rancher",
    # VDI / remote access
    "vmware vcenter", "vcenter server",
    "vmware horizon", "horizon view",
    "citrix workspace",
    "guacamole",
    # CMS / portals
    "liferay",
    "adobe experience manager", " aem ",
    "strapi",
    "directus",
    "ghost",
    "bookstack",
    # Enterprise SaaS
    "zoho",
    "servicenow",
    "sap netweaver", "sap web",
    # File transfer
    "moveit",
    "goanywhere",
    "fortra",
    # Reverse proxies / LB
    "varnish",
    "traefik",
    "haproxy",
    # Misc
    "nextcloud", "owncloud",
    "mattermost",
    "rocketchat",
    "solarwinds orion",
]

# ── Network-tier products ─────────────────────────────────────────────────────
# VPN gateways, firewalls, ADCs — devices commonly exposed to the internet.
# Stricter vuln-type requirements than web tier.
NETWORK_PRODUCTS = [
    "cisco asa", "cisco ios", "cisco rv", "cisco ftd", "cisco firepower",
    "cisco anyconnect", "cisco vmanage", "cisco sd-wan",
    "fortinet", "fortigate", "fortimanager", "fortianalyzer", "fortiproxy", "fortios",
    "citrix adc", "netscaler", "citrix gateway",
    "ivanti connect", "ivanti pulse", "pulse secure", "pulse connect",
    "f5 big-ip", "f5 bigip",
    "palo alto networks", "pan-os",
    "sonicwall",
    "juniper srx", "juniper junos",
    "watchguard",
    "barracuda",
    "check point", "checkpoint",
    "globalprotect",
    "openvpn",
]

# ── Vuln types ────────────────────────────────────────────────────────────────
WEB_VULN_TYPES = [
    "remote code execution", " rce ", "rce)",
    "code execution",
    "authentication bypass", "auth bypass", "unauthenticated access",
    "sql injection",
    "server-side request forgery", "ssrf",
    "xml external entity", " xxe",
    "path traversal", "directory traversal",
    "arbitrary file read", "arbitrary file write", "arbitrary file upload",
    "local file inclusion", "remote file inclusion",
    "deserialization", "deserializ",
    "unrestricted file upload", "file upload",
    "command injection", "os command",
    "template injection", "ssti",
    "code injection",
    "expression language injection",
    "jndi injection",
    "prototype pollution",
    "object injection",
    "ognl injection",
    "ldap injection",
    "privilege escalation",
    "open redirect",
    "arbitrary code",
]

# Stricter for network tier — must be unauthenticated RCE/bypass level
NETWORK_VULN_TYPES = [
    "remote code execution", " rce ", "rce)",
    "authentication bypass", "auth bypass",
    "pre-authentication",
    "unauthenticated remote",
    "arbitrary code execution",
    "command injection",
]

# ── Hard exclusions ───────────────────────────────────────────────────────────
# Skip these regardless of product/vuln match.
EXCLUDE_KEYWORDS = [
    "windows kernel",
    "linux kernel",
    "kernel privilege",
    "kernel memory",
    "uefi",
    "apple ios",
    "iphone",
    "ipad",
    " android ",
    "macos",
    "mac os x",
    "physical access",
    "requires physical",
    "local access required",
    "requires local access",
    "industrial control system",
    "scada",
    "programmable logic controller",
]

# ─────────────────────────────────────────────────────────────────────────────


def load_env():
    for p in (".env", "../.env"):
        fp = os.path.join(BASE_DIR, p)
        if os.path.exists(fp):
            for line in open(fp):
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
    try:
        raw = json.load(open(STATE_FILE))
    except Exception:
        return {"sent": {}, "poc": {}}
    sent = raw.get("sent", {})
    poc = raw.get("poc", {})
    # Migrate old format where sent values were dicts (first_seen, had_poc, etc.)
    new_sent = {}
    for k, v in sent.items():
        if isinstance(v, dict):
            new_sent[k] = v.get("first_seen", utcnow().isoformat())
            if k not in poc:
                poc[k] = v.get("had_poc", False)
        else:
            new_sent[k] = v
    return {"sent": new_sent, "poc": poc}


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    json.dump(state, open(tmp, "w"), indent=2)
    os.replace(tmp, STATE_FILE)


def fetch_nvd(params):
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    start = 0
    while True:
        p = dict(params, resultsPerPage=200, startIndex=start)
        try:
            r = requests.get(NVD_URL, params=p, headers=headers, timeout=30)
            r.raise_for_status()
        except Exception as e:
            print(f"NVD fetch error: {e}", file=sys.stderr)
            return
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return
        for v in vulns:
            yield v
        start += 200
        if start >= data.get("totalResults", 0):
            return


def best_cvss(metrics):
    """Return (score, vector) for the highest available CVSS v3 entry."""
    best_s, best_v = 0.0, ""
    for k in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(k, []):
            d = m.get("cvssData", {})
            s = d.get("baseScore", 0.0)
            if s > best_s:
                best_s = s
                best_v = d.get("vectorString", "")
    return best_s, best_v


def find_all(text, lst):
    t = text.lower()
    return [item for item in lst if item in t]


def find_one(text, lst):
    t = text.lower()
    for item in lst:
        if item in t:
            return item
    return None


def send_discord(text):
    if not WEBHOOK:
        return
    # Chunk if over Discord's limit
    chunks, buf = [], ""
    for line in text.split("\n"):
        candidate = (buf + "\n" + line) if buf else line
        if len(candidate) > MAX_LEN:
            if buf:
                chunks.append(buf)
            buf = line
        else:
            buf = candidate
    if buf:
        chunks.append(buf)
    for chunk in chunks:
        requests.post(WEBHOOK, json={"content": chunk})
        if len(chunks) > 1:
            time.sleep(0.5)


# ─────────────────────────────────────────────────────────────────────────────

ap = argparse.ArgumentParser(description="Web-focused CVE watcher for security researchers")
ap.add_argument("-min", type=float, default=8.5,
                help="Minimum CVSS score (default: 8.5)")
ap.add_argument("-window", type=int, default=25,
                help="Hours back to query NVD (default: 25)")
ap.add_argument("-tier", choices=["web", "network", "all"], default="all",
                help="Product tier to check (default: all)")
ap.add_argument("-why", action="store_true",
                help="Show which product/vuln keywords matched")
ap.add_argument("-new-only", action="store_true",
                help="Only alert on first-seen CVEs (skip PoC-upgrade alerts)")
ap.add_argument("-dry-run", action="store_true",
                help="Print matches but don't send to Discord or update state")
ap.add_argument("-debug", action="store_true",
                help="Print every CVE evaluated with its skip reason")
ap.add_argument("-clear-state", action="store_true",
                help="Reset dedup state and exit")
ap.add_argument("-send-test", action="store_true",
                help="Send a test Discord message and exit")
args = ap.parse_args()

if args.clear_state:
    json.dump({"sent": {}, "poc": {}}, open(STATE_FILE, "w"), indent=2)
    print("State cleared.")
    sys.exit(0)

if args.send_test:
    if not WEBHOOK:
        print("No Discord webhook configured.")
        sys.exit(1)
    send_discord("🧪 CVEWatch test message")
    print("Test message sent.")
    sys.exit(0)

# ── Fetch ─────────────────────────────────────────────────────────────────────
now = utcnow()
params = {
    "lastModStartDate": (now - datetime.timedelta(hours=args.window)).isoformat(),
    "lastModEndDate": now.isoformat(),
}

state = load_state()
sent = state["sent"]
poc_state = state["poc"]
alerted, checked = 0, 0

for item in fetch_nvd(params):
    c = item.get("cve", {})
    cid = c.get("id", "")
    if not cid:
        continue

    checked += 1

    desc_obj = next((d for d in c.get("descriptions", []) if d.get("lang") == "en"), {})
    desc = desc_obj.get("value", "") or c.get("descriptions", [{}])[0].get("value", "")

    score, vector = best_cvss(c.get("metrics", {}))

    def skip(reason):
        if args.debug:
            print(f"  SKIP {cid} (cvss={score}) — {reason}")

    # 1. CVSS + network + no-auth
    if score < args.min:
        skip(f"cvss {score} < {args.min}")
        continue
    if "AV:N" not in vector:
        skip("AV!=N")
        continue
    if "PR:N" not in vector:
        skip("PR!=N (requires auth)")
        continue

    # 2. Hard exclusion
    excl = find_one(desc, EXCLUDE_KEYWORDS)
    if excl:
        skip(f"excluded: {excl!r}")
        continue

    # 3. PoC / dedup logic
    has_poc = bool(POC_RE.search(desc))
    prev_seen = cid in sent
    prev_poc = poc_state.get(cid, False)
    poc_new = has_poc and not prev_poc

    # NVD backfills old CVEs when updating metadata (CVSS scores, references), causing them
    # to surface in lastModStartDate queries. Skip pre-2022 CVEs unless they have an active
    # PoC signal — those are worth knowing about even if old.
    try:
        cve_year = int(cid.split("-")[1])
        if cve_year < 2022 and not has_poc:
            skip(f"year {cve_year} < 2022 and no PoC (NVD backfill noise)")
            continue
    except (IndexError, ValueError):
        pass

    if args.new_only and prev_seen:
        skip("already seen (new-only mode)")
        continue
    if not args.new_only and prev_seen and not poc_new:
        skip("already alerted, no new PoC signal")
        continue

    # 4. Product + vuln type matching
    tier_label = None
    matched_products, matched_vulns = [], []

    if args.tier in ("web", "all"):
        wp = find_all(desc, WEB_PRODUCTS)
        wv = find_all(desc, WEB_VULN_TYPES)
        if wp and wv:
            tier_label = "WEB"
            matched_products, matched_vulns = wp, wv

    if tier_label is None and args.tier in ("network", "all"):
        np_ = find_all(desc, NETWORK_PRODUCTS)
        nv = find_all(desc, NETWORK_VULN_TYPES)
        if np_ and nv:
            tier_label = "NETWORK"
            matched_products, matched_vulns = np_, nv

    if tier_label is None:
        skip("no relevant product+vuln match")
        continue

    # ── Build alert ───────────────────────────────────────────────────────────
    poc_tag = " 🧨 PoC signal" if poc_new else (" 💥 PoC" if has_poc else "")
    header = f"[{tier_label}]{poc_tag} **{cid}** (CVSS {score})"
    msg = f"{header}\n{desc}\nhttps://nvd.nist.gov/vuln/detail/{cid}"
    if args.why:
        msg += f"\n**Products:** {', '.join(matched_products[:3])}"
        msg += f"\n**Vuln:** {', '.join(matched_vulns[:3])}"

    print(msg)
    print()
    alerted += 1

    if not args.dry_run:
        send_discord(msg)
        sent[cid] = now.isoformat()
        poc_state[cid] = has_poc

state["sent"] = sent
state["poc"] = poc_state
if not args.dry_run:
    save_state(state)

print(f"Done — {alerted} alert(s) from {checked} CVEs evaluated.")
