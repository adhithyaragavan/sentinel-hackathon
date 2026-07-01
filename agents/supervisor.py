"""
Supervisor Agent — final decision maker in the Sentinel pipeline.

Reads risk_score from the Remediation Planner output:
  risk_score < RISK_SCORE_THRESHOLD  → auto-remediate (log + mark done)
  risk_score >= RISK_SCORE_THRESHOLD → escalate: send real Slack webhook for human approval

Input:  {
    "alert":    <original EDR alert dict>,
    "triage":   <triage output>,
    "forensic": <forensic output>,
    "executor": <executor output>,
    "planner":  <planner output>
}
Output: {
    "alert_id":      str,
    "decision":      "auto_remediated" | "escalated",
    "action":        str,
    "target":        str,
    "risk_score":    float,
    "threshold":     float,
    "slack_notified": bool,
    "outcome":       str
}
"""

import sys
import os
import json
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_DEFAULT_THRESHOLD = 0.7


def _get_threshold() -> float:
    raw = os.environ.get("RISK_SCORE_THRESHOLD", str(_DEFAULT_THRESHOLD))
    try:
        return float(raw)
    except ValueError:
        return _DEFAULT_THRESHOLD


def _severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")


def _build_slack_payload(alert: dict, triage: dict, forensic: dict, executor: dict, planner: dict) -> dict:
    sev = triage.get("severity", "unknown")
    hostname   = alert.get("hostname", "unknown")
    username   = alert.get("username", "unknown")
    malware    = (forensic.get("hash_intel") or {}).get("malware_family", "Unknown")
    c2_ip      = next((i["value"] for i in forensic.get("iocs", []) if i["type"] == "ip"), "unknown")
    blocked    = len(executor.get("blocked_connections", []))
    action     = planner.get("action", "unknown")
    target     = planner.get("target", "unknown")
    risk       = planner.get("risk_score", 0.0)
    confidence = planner.get("confidence", 0.0)
    rationale  = planner.get("rationale", "")
    alert_id   = alert.get("alert_id", "unknown")

    secondary = "\n".join(
        f"  • `{s.get('action')}` on `{s.get('target')}` — {s.get('reason', '')}"
        for s in planner.get("secondary_actions", [])
    ) or "  _None_"

    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{_severity_emoji(sev)}  SENTINEL ALERT — Human Approval Required",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID*\n`{alert_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity*\n{sev.upper()}"},
                    {"type": "mrkdwn", "text": f"*Host*\n`{hostname}`"},
                    {"type": "mrkdwn", "text": f"*User*\n`{username}`"},
                    {"type": "mrkdwn", "text": f"*Malware Family*\n`{malware}`"},
                    {"type": "mrkdwn", "text": f"*C2 IP*\n`{c2_ip}`"},
                ],
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Sandbox Verdict*\n`{executor.get('verdict', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Blocked C2 Connections*\n`{blocked}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score*\n`{risk:.2f} / 1.00`"},
                    {"type": "mrkdwn", "text": f"*Planner Confidence*\n`{confidence:.0%}`"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action*\n>`{action}` on `{target}`\n\n*Rationale*\n{rationale}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Secondary Actions*\n{secondary}",
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Sentinel Autonomous SOC  •  MITRE: {', '.join(triage.get('mitre', []))}",
                    }
                ],
            },
        ]
    }


def _send_slack(payload: dict, webhook_url: str) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Slack returned HTTP {resp.status}")


def run(inputs: dict) -> dict:
    alert    = inputs["alert"]
    triage   = inputs["triage"]
    forensic = inputs["forensic"]
    executor = inputs["executor"]
    planner  = inputs["planner"]
    alert_id = alert.get("alert_id", "UNKNOWN")

    threshold  = _get_threshold()
    risk_score = planner.get("risk_score", 0.0)
    action     = planner.get("action", "unknown")
    target     = planner.get("target", "unknown")

    slack_notified = False

    if risk_score < threshold:
        decision = "auto_remediated"
        outcome  = (
            f"Auto-remediated: '{action}' executed on '{target}'. "
            f"Risk score {risk_score:.2f} is below threshold {threshold}."
        )
    else:
        decision = "escalated"
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
        if not webhook_url:
            outcome = (
                f"ESCALATED (Slack skipped — SLACK_WEBHOOK_URL not set). "
                f"Risk score {risk_score:.2f} >= threshold {threshold}. "
                f"Recommended: '{action}' on '{target}'."
            )
        else:
            payload = _build_slack_payload(alert, triage, forensic, executor, planner)
            _send_slack(payload, webhook_url)
            slack_notified = True
            outcome = (
                f"Escalated to Slack for human approval. "
                f"Risk score {risk_score:.2f} >= threshold {threshold}. "
                f"Recommended: '{action}' on '{target}'."
            )

    return {
        "alert_id":       alert_id,
        "decision":       decision,
        "action":         action,
        "target":         target,
        "risk_score":     risk_score,
        "threshold":      threshold,
        "slack_notified": slack_notified,
        "outcome":        outcome,
    }


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    alert_path = os.path.join(os.path.dirname(__file__), "..", "mock_data", "edr_alert.json")
    with open(alert_path) as f:
        alert = json.load(f)

    mock_triage = {
        "severity": "critical",
        "classification": "Phishing-delivered RAT with C2 beacon",
        "confidence": 0.97,
        "mitre": alert["mitre_techniques"],
    }
    mock_forensic = {
        "iocs": [
            {"type": "ip",           "value": "185.220.101.47"},
            {"type": "registry_key", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ],
        "hash_intel": {"malicious": True, "malware_family": "AsyncRAT", "vendor_detections": 54, "total_vendors": 72},
        "ip_intel":   {"abuse_confidence_score": 97},
        "mitre":      alert["mitre_techniques"],
        "evidence_summary": "AsyncRAT beaconing to Tor-exit C2 node.",
    }
    mock_executor = {
        "verdict": "malicious",
        "detonation_status": "completed",
        "blocked_connections": [{"dst_host": "185.220.101.47", "dst_port": "4444"}],
    }
    mock_planner = {
        "action":     "isolate_host",
        "target":     "WORKSTATION-04",
        "risk_score": 0.95,
        "confidence": 0.97,
        "rationale":  (
            "AsyncRAT is actively beaconing to a known C2 infrastructure. "
            "Persistence via registry Run key means killing the process alone is insufficient. "
            "Host isolation is required immediately to prevent lateral movement and data exfiltration."
        ),
        "secondary_actions": [
            {"action": "block_ip",       "target": "185.220.101.47",                                    "reason": "C2 endpoint"},
            {"action": "quarantine_file","target": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice_june.pdf.exe", "reason": "Malware binary"},
            {"action": "disable_user",   "target": "jsmith",                                             "reason": "Compromised account"},
        ],
    }

    output = run({
        "alert":    alert,
        "triage":   mock_triage,
        "forensic": mock_forensic,
        "executor": mock_executor,
        "planner":  mock_planner,
    })
    print(json.dumps(output, indent=2))
