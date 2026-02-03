#!/usr/bin/env python3
import os, sys, json, argparse, requests, datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", ".env"))
STATE_FILE = os.path.join(BASE_DIR, "state.json")
UTC = datetime.timezone.utc

def load_env():
    if os.path.exists(ENV_PATH):
        for l in open(ENV_PATH):
            l = l.strip()
            if not l or l.startswith("#") or "=" not in l:
                continue
            k, v = l.split("=", 1)
            v = v.strip().strip('"').strip("'")  # <-- CRITICAL FIX
            os.environ[k] = v

load_env()

WEBHOOK = os.getenv("DISCORD_WEBHOOK_CVES")

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
    json.dump({"sent": [], "sent_at": {}}, open(STATE_FILE, "w"))
    print("✅ State cleared")
    sys.exit(0)

if args.send_test:
    if not WEBHOOK:
        print("❌ DISCORD_WEBHOOK_CVES missing")
        sys.exit(1)
    requests.post(WEBHOOK, json={"content": "🧪 CVEWatch test message"})
    print("✅ Test message sent")
    sys.exit(0)

print("ℹ️ CVE fetch logic unchanged (intentionally)")
