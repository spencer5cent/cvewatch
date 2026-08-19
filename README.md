# CVEWatch

CVEWatch polls NVD for high-impact network-reachable web and network CVEs and
sends deduplicated Discord alerts.

It alerts when a matching CVE is first seen or when a later NVD update adds a
strong PoC/exploit signal. PoC detection uses both description text and
reference deltas: NVD `Exploit` tags plus conservative exploit/PoC URL shapes.
Existing state is baselined when reference tracking is first deployed, so it
does not replay the historical catalog.

`state.json` stores first-alert timestamps, PoC booleans, and the strong exploit
reference set last observed for each CVE. NVD pages are retried three times. A
terminal page-fetch failure exits nonzero after preserving already processed
state, allowing systemd to expose partial feed failures instead of treating a
zero-alert partial run as healthy.

Common usage:

```bash
# Inspect the last day without Discord or state changes.
python3 cve_watch.py -window 24 -dry-run -why

# Normal stateful alerting.
python3 cve_watch.py -window 26 -why

# Restrict to web or network products.
python3 cve_watch.py -window 24 -tier web
python3 cve_watch.py -window 24 -tier network
```

The VPS runs an hourly daytime timer with a two-hour overlap and an 08:00 daily
26-hour catch-up timer.
