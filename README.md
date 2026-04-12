# Detect_HTTP_Beaconing

MIME/content-type mismatch (Zeek/http)


Assumes fields: http_host, http_uri, http_resp_mime_types, src_ip

```jsx
index=zeek sourcetype=zeek:http earliest=-7d@d
| eval uri=coalesce(http_uri, uri, url)
| eval mime=coalesce(http_resp_mime_types, resp_mime_types)
| eval ext=lower(if(match(uri, “\.(png|jpg|jpeg|gif|svg|css|json|js|wasm)$”), replace(uri, “.*\.”, “”), “”))
| where (ext IN (“png”,”jpg”,”jpeg”,”gif”,”svg”) AND NOT match(mime, “^image/”)) OR (ext=”js” AND NOT match(mime, “(javascript|ecmascript)”)) OR (ext=”css” AND NOT match(mime, “css”))
| stats count by src_ip http_host uri mime ext
| where count > 1
| lookup whitelist_domains domain AS http_host OUTPUT domain AS whitelisted
| where isnull(whitelisted)
| table src_ip http_host uri mime ext count
```
Notes:
If Zeek field names differ, swap.
 Use this to find suspicious content masquerading as images/JS/etc.

 
 - - - Whitelist/lookups & enrichment - - -
Maintain lookup files:
 whitelist_domains.csv (domain,reason,added_by)
 whitelist_ips.csv (ip,reason,added_by)
 Use | lookup whitelist_ips ip AS client OUTPUT ip AS whitelisted to suppress alerts.
 Enrich results with threat intel: | lookup threat_intel_ips ip AS client OUTPUT threat,score
Name: Detect_HTTP_Beaconing_to_Analytics
 Schedule: run every 15 minutes
 Trigger: number of results > 0
 Actions: notable event, add to investigation, email to IR team
 Suppression: if client in whitelist_ips or host in whitelist_domains

 
 - - - False positives & tuning guidance - - -
Whitelist known analytics/monitoring agents (but audit whitelist additions).
 Combine signals for higher confidence: beacon + mime mismatch + uncommon port + EDR process correlation.
 Baseline volume per client class: workstations vs servers - tune thresholds per class.
 Use moving thresholds: weekly percentile baselines for counts.
