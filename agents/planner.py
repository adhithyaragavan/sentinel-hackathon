"""
Remediation Planner Agent — decides what action to take and scores the risk.

Synthesizes triage + forensic + executor outputs via NIM to produce a structured
remediation plan. The Supervisor Agent uses risk_score to decide auto-remediate
vs. human escalation.

Input:  {
    "alert":    <original EDR alert dict>,
    "triage":   <triage agent output dict>,
    "forensic": <forensic examiner output dict>,
    "executor": <tool-executor output dict>
}
Output: {
    "alert_id":          str,
    "action":            str,    # primary action (see ACTION_* constants below)
    "target":            str,    # what to act on (hostname, PID, IP, file path)
    "risk_score":        float,  # 0.0–1.0  (Supervisor threshold is in .env)
    "confidence":        float,  # 0.0–1.0
    "rationale":         str,    # one-paragraph justification
    "secondary_actions": list[dict]  # additional recommended steps
}

Primary action values:
  isolate_host      — sever host from network
  kill_process      — terminate the malicious PID
  quarantine_file   — move file to quarantine vault
  block_ip          — push C2 IP to firewall block list
  escalate          — requires human decision before acting
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import nemoclaw

_SYSTEM_PROMPT = """You are a senior incident responder deciding how to contain a confirmed malware infection.

Given a JSON summary of triage, forensic, and sandbox detonation results, output ONLY a valid JSON object with:
- action: one of "isolate_host", "kill_process", "quarantine_file", "block_ip", "escalate"
- target: the specific asset to act on (e.g. hostname, PID as string, file path, or IP)
- risk_score: float 0.0-1.0 representing containment urgency (1.0 = act immediately, no human needed)
- confidence: float 0.0-1.0 representing your confidence in this recommendation
- rationale: one paragraph explaining the chosen action and why it is proportionate
- secondary_actions: list of objects {action, target, reason} for follow-on steps

Risk score guidance:
  0.9-1.0  confirmed active C2, high-confidence hash, persistence established
  0.7-0.89 strong indicators but missing one confirmation signal
  0.5-0.69 suspicious but ambiguous — lean toward escalate
  < 0.5    insufficient evidence — always escalate

For "target", prefer the most impactful single asset. If the host is actively beaconing,
isolate_host beats kill_process since the process may respawn via the persistence mechanism.

Output ONLY the JSON object. No markdown, no explanation."""


def _build_summary(alert: dict, triage: dict, forensic: dict, executor: dict) -> dict:
    return {
        "alert_id": alert.get("alert_id"),
        "hostname": alert.get("hostname"),
        "username": alert.get("username"),
        "triage": {
            "severity": triage.get("severity"),
            "classification": triage.get("classification"),
            "confidence": triage.get("confidence"),
        },
        "forensic": {
            "malware_family": (forensic.get("hash_intel") or {}).get("malware_family"),
            "hash_malicious": (forensic.get("hash_intel") or {}).get("malicious"),
            "vendor_detections": (forensic.get("hash_intel") or {}).get("vendor_detections"),
            "c2_ip": next(
                (ioc["value"] for ioc in forensic.get("iocs", []) if ioc["type"] == "ip"),
                None,
            ),
            "c2_abuse_score": (forensic.get("ip_intel") or {}).get("abuse_confidence_score"),
            "persistence": [
                ioc["value"]
                for ioc in forensic.get("iocs", [])
                if ioc["type"] == "registry_key"
            ],
            "mitre": forensic.get("mitre", []),
        },
        "sandbox": {
            "verdict": executor.get("verdict"),
            "blocked_connections": executor.get("blocked_connections", []),
            "detonation_status": executor.get("detonation_status"),
        },
    }


def run(inputs: dict) -> dict:
    alert    = inputs["alert"]
    triage   = inputs["triage"]
    forensic = inputs["forensic"]
    executor = inputs["executor"]
    alert_id = alert.get("alert_id", "UNKNOWN")

    summary = _build_summary(alert, triage, forensic, executor)
    user_prompt = f"Plan remediation for this incident:\n{json.dumps(summary, indent=2)}"
    result = nemoclaw.infer_json(_SYSTEM_PROMPT, user_prompt)

    return {
        "alert_id": alert_id,
        "action": result["action"],
        "target": str(result["target"]),
        "risk_score": float(result["risk_score"]),
        "confidence": float(result["confidence"]),
        "rationale": result["rationale"],
        "secondary_actions": result.get("secondary_actions", []),
    }


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    alert_path = os.path.join(os.path.dirname(__file__), "..", "mock_data", "edr_alert.json")
    with open(alert_path) as f:
        alert = json.load(f)

    mock_triage = {
        "alert_id": alert["alert_id"],
        "severity": "critical",
        "classification": "Phishing-delivered RAT with C2 beacon",
        "confidence": 0.97,
        "duplicate": False,
        "summary": "Outlook spawned a suspicious unsigned executable that beaconed to a known C2 IP.",
        "mitre": alert["mitre_techniques"],
    }
    mock_forensic = {
        "alert_id": alert["alert_id"],
        "iocs": [
            {"type": "hash",         "value": alert["process"]["sha256"]},
            {"type": "ip",           "value": "185.220.101.47", "context": "port 4444 / TCP"},
            {"type": "registry_key", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ],
        "hash_intel": {"malicious": True, "malware_family": "AsyncRAT", "vendor_detections": 54, "total_vendors": 72},
        "ip_intel":   {"malicious": True, "abuse_confidence_score": 97},
        "mitre":      alert["mitre_techniques"],
        "evidence_summary": "AsyncRAT dropped via phishing attachment, beaconing to Tor-exit C2.",
    }
    mock_executor = {
        "alert_id": alert["alert_id"],
        "verdict": "malicious",
        "detonation_status": "completed",
        "blocked_connections": [{
            "dst_host": "185.220.101.47",
            "dst_port": "4444",
            "deny_reason": "connection refused by sandbox network policy",
        }],
        "verdict_reason": "Confirmed AsyncRAT: 1 C2 connection blocked. Hash flagged by 54/72 vendors.",
    }

    output = run({
        "alert": alert,
        "triage": mock_triage,
        "forensic": mock_forensic,
        "executor": mock_executor,
    })
    print(json.dumps(output, indent=2))
