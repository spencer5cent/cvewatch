CVEWatch Tracks CVEs and alerts when they get more 
interesting (like when PoCs appear). What it does
	∙ Pulls CVEs from NVD ∙ Filters by CVSS, 
	exploitability, keywords, year ∙ Maintains 
	state file to avoid duplicate alerts ∙ Alerts 
	on NEW or POC_ADDED only ∙ Discord 
	notifications optional
State File Tracks what you’ve seen before: 
	∙ First seen timestamp 
	∙ PoC status
Alerts trigger when: 
	∙ CVE is new 
	∙ PoC appears after 
	initial discovery
Common Usage
Fill state (no alerts):

cvewatch -min 5 -no-auth -year 2010-$(date +%Y) -dry-run

Daily check: 
cvewatch -min 7 -remote -no-auth -poc

Run via Cron: 0 */6 * * * /path/to/cvewatch -min 7 
-remote -no-auth -poc
