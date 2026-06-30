"""
Triage Agent — classifies an incoming EDR alert by severity and deduplicates.

Input:  EDR alert dict (see mock_data/edr_alert.json for schema)
Output: {
    "alert_id":       str,
    "severity":       "critical" | "high" | "medium" | "low",
    "classification": str,   # one-line human label, e.g. "Phishing-delivered RAT with C2 beacon"
    "confidence":     float, # 0.0–1.0
    "duplicate":      bool,
    "summary":        str,   # 2–3 sentence narrative for downstream agents
    "mitre":          list[str]
}
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import nemoclaw

# Simple in-process dedup store. In production this would be Redis/DB.
_seen_alert_ids: set[str] = set()

_SYSTEM_PROMPT = """You are a senior SOC analyst. Given an EDR alert in JSON format, output ONLY valid JSON with these fields:
- severity: one of "critical", "high", "medium", "low"
- classification: a concise threat label (e.g. "Phishing-delivered RAT with C2 beacon")
- confidence: float 0.0-1.0 representing your classification confidence
- summary: 2-3 sentences describing what happened, what the threat is, and why it's dangerous

Base severity on: process lineage, network IOCs, persistence mechanisms, MITRE techniques, and file system changes.
Output ONLY the JSON object. No markdown, no explanation."""


def run(alert: dict) -> dict:
    alert_id = alert.get("alert_id", "UNKNOWN")

    is_duplicate = alert_id in _seen_alert_ids
    _seen_alert_ids.add(alert_id)

    if is_duplicate:
        return {
            "alert_id": alert_id,
            "severity": "low",
            "classification": "Duplicate alert — already processed",
            "confidence": 1.0,
            "duplicate": True,
            "summary": f"Alert {alert_id} was already triaged in this session. No further action needed.",
            "mitre": alert.get("mitre_techniques", []),
        }

    user_prompt = f"Triage this EDR alert:\n{json.dumps(alert, indent=2)}"
    result = nemoclaw.infer_json(_SYSTEM_PROMPT, user_prompt)

    return {
        "alert_id": alert_id,
        "severity": result["severity"],
        "classification": result["classification"],
        "confidence": float(result["confidence"]),
        "duplicate": False,
        "summary": result["summary"],
        "mitre": alert.get("mitre_techniques", []),
    }


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    alert_path = os.path.join(os.path.dirname(__file__), "..", "mock_data", "edr_alert.json")
    with open(alert_path) as f:
        alert = json.load(f)

    output = run(alert)
    print(json.dumps(output, indent=2))
