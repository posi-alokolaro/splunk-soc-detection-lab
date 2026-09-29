# Incident Investigation: Remote MSHTA Execution

## Summary

A Splunk investigation of Windows Sysmon process-creation telemetry identified suspicious use of `mshta.exe`.

The process executed a remote HTA resource over HTTPS and was spawned by the Windows Management Instrumentation process `WmiPrvSE.exe`.

The activity came from a controlled Atomic Red Team / Attack Range dataset and represents simulated adversary behavior.

## Affected System

- Host: `win-dc-283.attackrange.local`
- User: `ATTACKRANGE\Administrator`

## Process Chain

```text
WmiPrvSE.exe
      |
      v
  mshta.exe
      |
      v
Remote HTA resource over HTTPS
