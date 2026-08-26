## Summary

### Hypothesis
An adversary delivered a malicious Microsoft Office attachment via spearphishing. When opened, 
the Office process made an outbound DNS query to a non-Microsoft domain to stage a secondary 
payload — consistent with a maldoc-to-RAT delivery chain.

### Approach
- **Part 1 (Bronze/Silver):** Loaded raw Sysmon-via-Cribl JSONL (`sysmon_spearphish_cribl.json`, 
  28,017 events across 12 Sysmon EventCodes). Parsed the nested `_raw` JSON field into a flat, 
  typed Silver-layer DataFrame (`sysmon_silver`) covering process creation (EventCode 1), 
  DNS query (EventCode 22), and network connection (EventCode 3) events.
- **Part 2 (Detection):** Built a base query to isolate Office process launches (WINWORD.EXE, 
  EXCEL.EXE, etc.), then filtered DNS queries made by those same processes to exclude known 
  Microsoft-owned domains (`*.office.com`, `*.msedge.net`, etc.). Correlated the two on 
  `ProcessGuid` (not `ProcessId`, to avoid false joins from PID reuse) to link a specific 
  Office launch to its subsequent DNS activity.
- **Part 3 (Normalization, Alerting, Enrichment):**
  - Normalized detection output to OCSF-inspired field names (`device_name`, `actor_user`, 
    `process_name`, `dns_query`, etc.) and mapped behavior to MITRE ATT&CK 
    (T1566.001 – Spearphishing Attachment, T1071.004 – App Layer Protocol: DNS).
  - Packaged the result into an analyst-ready alert table with `alert_id`, `severity`, 
    `mitre_technique`, and a human-readable `alert_description`.
  - Enriched the flagged domain via VirusTotal (detection votes, category, domain 
    registration date, registrar).

### Finding
Out of 28,017 raw events, exactly **one high-fidelity alert** fired:

> `WINWORD.EXE` (parent: `explorer.exe`) was launched with command line referencing 
> `C:\Temp\asyncrat\loader\asyncrat.doc`, and the same process subsequently queried 
> `www.mediafire.com` — a non-Microsoft domain not present in the DNS query exclusion list.

The filename itself (`asyncrat.doc`) strongly suggests AsyncRAT, a known commodity remote 
access trojan, staged via a legitimate file-hosting service (mediafire) to blend in with 
normal traffic.

### Enrichment results
VirusTotal enrichment on `www.mediafire.com` returned:
- **2 vendors** flagged the domain malicious, **59** flagged it harmless, **0** suspicious — 
  a low but non-zero malicious signal, consistent with a legitimate service occasionally 
  abused rather than a purpose-built malicious domain.
- **Reputation score: 62** (positive/trusted range).
- **Category:** uncategorized.
- **Domain created: 2002-08-11**, registered via Cloudflare, Inc. — over 20 years old, 
  confirming this is a long-established legitimate service, not attacker-registered 
  infrastructure.
