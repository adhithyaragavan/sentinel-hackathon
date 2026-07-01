# Sentinel — Architecture & Safety Design

## Design goal

Compress the human SOC triage-to-containment loop — normally 20–40 minutes of
analyst work — into a few autonomous seconds, while keeping a human in the loop
for high-risk actions. The system is a linear agent pipeline: each stage consumes
a structured JSON packet and emits one, so every agent is independently testable
and the full run produces an auditable evidence trail.

## Pipeline

```
EDR alert ─► Triage ─► Forensic ─► Tool-Executor ─► Planner ─► Supervisor ─► action
             (NIM)      (NIM)       (OpenShell)      (NIM)       (Slack / auto)
```

| Stage | Input | Output | External call |
|-------|-------|--------|---------------|
| Triage | EDR alert | severity, classification, dedupe flag | NIM |
| Forensic | alert + triage | IOCs, process tree, threat-intel | NIM + threat-intel |
| Tool-Executor | alert + forensic | verdict, blocked connections | **OpenShell sandbox** |
| Planner | all prior | action, risk_score, rationale | NIM |
| Supervisor | all prior | decision, Slack notification | **Slack webhook** |

## Why a linear pipeline (not a graph)

For a SOC containment workflow the stages have a strict data dependency: you cannot
plan remediation before you have a sandbox verdict, and you cannot get a verdict
before you have the file hash from forensics. A linear chain makes the evidence
trail deterministic and the demo legible. Concurrency would only matter for
multi-incident handling, which is out of scope (see limitations).

## Safety design (NemoClaw / OpenShell)

The Tool-Executor is the only stage that runs untrusted code — the suspected
malware. Everything dangerous is confined there, inside an OpenShell sandbox.
OpenShell provides the four safety boundaries NemoClaw is built around:

1. **Network egress control.** The sandbox policy (`sandbox_policy/detonation.yaml`)
   declares *no* `network_policies`, which means default-deny. When the detonated
   sample tries to beacon to its C2 (`185.220.101.47:4444`), the connection is
   refused at the kernel level. This is verifiable live and is the core evidence
   that the file is malicious.

2. **Filesystem scope.** Landlock restricts the sandbox to `/sandbox` and `/tmp`
   read-write, with system paths read-only. Malware persistence attempts land in a
   throwaway namespace, never the host.

3. **Credentials isolation.** No host credentials, API keys, or environment secrets
   are mounted into the sandbox. The `.env` (NIM key, Slack webhook) stays in the
   orchestrator process only.

4. **Human control / approval gates.** The Supervisor enforces the final gate:
   any incident scoring at or above `RISK_SCORE_THRESHOLD` (default 0.7) is not
   auto-actioned — it is escalated to a human via Slack with the full evidence
   packet. The agent recommends; the human approves.

## Trust boundary

```
┌─────────────────────────────────────────────┐
│ Orchestrator (trusted)                        │
│  - holds NIM key + Slack webhook              │
│  - runs Triage, Forensic, Planner, Supervisor │
│                                               │
│   ┌───────────────────────────────────────┐  │
│   │ OpenShell sandbox (untrusted)          │  │
│   │  - runs the suspected malware          │  │
│   │  - default-deny network                │  │
│   │  - no host credentials                 │  │
│   │  - ephemeral filesystem                │  │
│   └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Reliability / evaluation

`eval/evaluate.py` runs the full pipeline against a fixed alert and scores nine
correctness checks (severity, IOC count, malware family, sandbox verdict, blocked
connection, planner action, risk score, supervisor decision) plus per-agent
latency. This is the "small but believable evaluation loop" — it catches
regressions in any stage and gives a single accuracy number.

## Known limitations

- OpenShell is alpha — single-developer, single-environment; no concurrent
  multi-incident handling.
- Demo data is synthetic, not a live SIEM feed.
- Threat-intel is stubbed (VirusTotal / AbuseIPDB-shaped fixtures), not live APIs.
