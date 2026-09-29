# Splunk SOC Detection & Investigation Lab

## Overview

This project demonstrates a SOC-style investigation using Splunk Cloud and Windows Sysmon telemetry.

The goal was to ingest endpoint security logs, hunt for suspicious process activity, investigate a parent-child execution chain, create reusable SPL detections, configure an alert, and map the findings to MITRE ATT&CK.

The dataset represents controlled Atomic Red Team / Attack Range activity and does not represent a real compromise.

## Tools & Technologies

- Splunk Cloud
- Windows Sysmon telemetry
- SPL (Search Processing Language)
- MITRE ATT&CK
- Splunk Attack Data / Atomic Red Team
- GitHub

## Dataset

A Windows Sysmon attack dataset was uploaded into a dedicated Splunk index:

`index=soc_lab`

Approximately **17,958 Sysmon events** were ingested for investigation.

## Investigation Workflow

The investigation followed this process:

1. Ingest Sysmon telemetry into Splunk.
2. Search for `mshta.exe` activity.
3. Filter for Sysmon Event ID 1 process-creation events.
4. Extract relevant fields from raw XML using SPL.
5. Identify suspicious command-line activity.
6. Analyze parent-child process relationships.
7. Detect remote HTA execution.
8. Create reusable detection searches.
9. Configure a scheduled Splunk alert.
10. Map the behavior to MITRE ATT&CK.

## Key Finding

A suspicious process chain was identified:

```text
WmiPrvSE.exe
      |
      v
  mshta.exe
      |
      v
Remote HTA resource over HTTPS
