CVEWatch tracks CVEs and alerts when they become more interesting
(e.g. new CVE, PoC appears, exploitability increases).

What it does
  ∙ Pulls CVEs from NVD (with pagination)
  ∙ Filters by CVSS, network attack vector, auth requirements
  ∙ Maintains a state file to avoid duplicate alerts
  ∙ Alerts only on meaningful changes (NEW, PoC added)
  ∙ Optional digest mode for awareness
  ∙ Discord notifications optional

State File
Tracks what you’ve seen before:
  ∙ First seen timestamp
  ∙ PoC status
  ∙ Last alerted state

Alert Triggers
Alerts fire only when:
  ∙ CVE is first seen (NEW)
  ∙ PoC appears after initial discovery

Digest Mode
Stateless awareness mode:
  ∙ Ignores state
  ∙ Shows all matching CVEs in a time window
  ∙ Includes full CVE details
  ∙ Output is chunked to avoid Discord limits

Common Usage

Fill state (no alerts):
cvewatch -window 8760 -min 5 -no-auth -dry-run

Hourly alerting (fast signal):
cvewatch -window 24 -min 7 -no-auth -poc -why

Digest / awareness run:
cvewatch -window 12 -min 5 --digest

Automation
Designed to run via systemd timers or cron.
