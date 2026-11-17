---
name: edr-bypass-re
description: "Invoke this skill for authorized adversary-simulation work that must understand and evaluate endpoint defense telemetry: mapping what an EDR or AV actually monitors (user-mode hooks, kernel callbacks, ETW providers, AMSI), surveying installed hooks from memory, and evaluating countermeasure combinations in an isolated lab, mapped to MITRE ATT&CK T1562."
---

# EDR Bypass RE (defense telemetry analysis for authorized adversary simulation)

Reverse the defender's implementation first, then reason about countermeasures. This skill covers the RE half (what the EDR monitors and how its components are built) and the evaluation half (which countermeasure classes defeat which telemetry, verified in an isolated lab). Maps to MITRE ATT&CK T1562.001, T1562.006, T1055, T1027.

Attribution: adapted from the `edr-bypass-re` playbook of [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT License).

## Boundaries (read first)

- **Authorized environments only**: your own lab machines/VMs, or hosts covered by written engagement scope (SoW, test contract, program scope statement). Never applied to unowned or out-of-scope systems.
- ARTEX/Ares tasks run in a Linux container. Every step here needs an **authorized Windows lab VM** reachable from the task environment; if none is provisioned, report the gap and stop.
- The deliverable is measurement and a report: which telemetry sources detected which technique, at what stage, with what fidelity.
- Report placeholders only: `{target_ip}`, `{hostname}`, `{user}`. Anonymize before anything leaves the lab.

## Applicable task types

1. Purple-team and detection-gap assessment: measure what the deployed EDR actually catches.
2. Product security evaluation: test your own endpoint product against known technique classes.
3. CTF or exercise scenarios requiring execution on hardened hosts, within the exercise rules.

**Not applicable**: evasion against systems outside written authorization; building mass-distributed malware.

## The four telemetry surfaces and countermeasure classes

| EDR monitoring surface | Countermeasure class (lab evaluation) |
|---|---|
| user-mode ntdll inline hooks | fresh ntdll copy from disk (unhook); direct/indirect syscall stubs with dynamic SSNs; hardware-breakpoint redirection |
| kernel callbacks (process, thread, image, registry) | call-stack spoofing; routing through legitimate trigger chains |
| ETW telemetry (Threat-Intelligence and others) | EtwEventWrite patching; provider teardown via NtTraceControl |
| AMSI scanning (amsi.dll) | AmsiScanBuffer patching; hardware-breakpoint redirection; loading a clean amsi.dll copy |

## Workflow

**Step 1**: identify the defenses on the lab host.
```powershell
Get-Service | Where-Object {$_.Name -match 'CSAgent|SentinelAgent|elasticendpoint|MsMpEng|wdsvc|cyserver|sysmon'}
fltmc filters
```

**Step 2**: survey user-mode hooks. Dump in-memory `ntdll.dll` from a process carrying the EDR's injected DLL, diff against on-disk copy. `pe-sieve64.exe /pid <pid> /shellc 3 /modules 3 /dir hooks_dump` automates the sweep.

**Step 3**: select the countermeasure combination to evaluate based on the telemetry surface table above.

**Step 4**: implement in the test harness. Reference implementations: SysWhispers3 for syscall stub generation, Hell's Gate/Halo's Gate for dynamic SSN resolution, Ekko for sleep-time memory obfuscation. Cite exact references used.

**Step 5**: verify in the isolated lab. Record every alert source that fires: AMSI, ETW-TI, Sysmon events 1/7/8/10, the EDR console. Negative results are results.

**Step 6**: write the evaluation. Map every observed detection to MITRE ATT&CK and hand the detection-gap list to the engagement owner.

## Completion self-check

- [ ] every technique run in the lab has a recorded observation with the telemetry source named
- [ ] the report contains placeholders only, never real hostnames or IPs
- [ ] nothing was executed outside the authorized lab VMs
