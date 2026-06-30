# Sentinel — Autonomous SOC Incident Response Swarm

## What this is
Hackathon project for NVIDIA/gnani.ai/OpenACC Agentic AI Open Hackathon, Track A
(Agentic Workflows). 5-agent swarm that autonomously triages a SOC alert, detonates
a suspicious file in an isolated sandbox, scores containment risk, and either
auto-remediates or escalates to a human via Slack. Built in ~1 day for a live demo.

## Architecture
Linear pipeline, one agent hands off to the next:

1. **Triage Agent** — reads mock EDR alert JSON, classifies severity, dedupes
2. **Forensic Examiner Agent** — builds evidence packet (process tree, file hash,
   suspicious IP) by querying stubbed threat-intel responses
3. **Tool-Executor Agent** — detonates the file inside an OpenShell sandbox with a
   default-deny network policy; this is the demo's money shot — show the blocked
   outbound connection live
4. **Remediation Planner Agent** — outputs structured JSON:
   `{action, target, risk_score, confidence}`
5. **Supervisor Agent** — risk_score < threshold → auto-remediate; else → real Slack
   webhook for human approval

## Stack (use ONLY these — do not add Triton, TensorRT-LLM, CUDA, Milvus, NeMo
Retriever, or anything else not listed here; this is a Track A orchestration
project, not Track B model training)
- **NVIDIA NemoClaw** — orchestration + Privacy Router. Privacy Router is
  configured to always route inference to cloud-hosted Nemotron via NVIDIA NIM
  (build.nvidia.com). No local GPU.
- **NVIDIA OpenShell** — kernel-level sandbox isolation (Landlock + seccomp +
  network namespaces) for the Tool-Executor Agent's detonation step. Installed
  locally via Docker.
- **Python** for agent logic and orchestration glue.
- Inference-only. No fine-tuning, no training data, no datasets to manage.

## Project structure
```
/agents/          one file per agent (triage.py, forensic.py, executor.py,
                  planner.py, supervisor.py)
/mock_data/       synthetic EDR alert JSON, stubbed threat-intel responses
/sandbox_policy/  OpenShell YAML policy for the Tool-Executor sandbox
/pipeline.py      orchestrates the 5 agents in sequence
.env              NVIDIA NIM API key, Slack webhook URL (never commit this)
```

## Conventions
- Each agent is a single function taking a structured input dict and returning a
  structured output dict — keep them independently testable.
- All inter-agent communication is JSON. No free-text handoffs.
- Real Slack webhook for the Supervisor's escalation step — not mocked, this needs
  to work live in the demo.
- Mock data only for the EDR feed and threat-intel responses; everything else
  (sandbox execution, Slack call, NIM inference calls) should be real.

## Demo scenario
Phishing email → malicious attachment opened → malware drops and starts beaconing
to a C2 IP → EDR alert fires → swarm runs end-to-end → host isolation decision
made within seconds, full evidence trail shown.

## Known limitations (don't try to fix these — they're acknowledged in the deck)
- OpenShell is alpha software: single-developer, single-environment. No concurrent
  multi-incident handling.
- Demo data is synthetic, not a live SIEM feed.

## Workflow preferences
- Build and test one agent at a time. Don't scaffold all 5 before the first one runs.
- Ask before installing new dependencies or making destructive changes.
- When something goes wrong with NemoClaw/OpenShell setup, check the official docs
  before guessing — this is unfamiliar territory for the team.
- Always commit working state before trying something risky.
