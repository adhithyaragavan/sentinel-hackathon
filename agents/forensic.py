"""
Forensic Examiner Agent — enriches the triage output into a full evidence packet.

Queries stubbed threat-intel for file hash and IP reputation, builds the process
tree from the raw alert, then calls NIM to synthesize an analyst-grade summary.

Input:  {
    "alert":  <original EDR alert dict>,
    "triage": <triage agent output dict>
}
Output: {
    "alert_id":        str,
    "process_tree":    list[dict],   # parent → child chain
    "iocs":            list[dict],   # hashes, IPs, paths, registry keys
    "hash_intel":      dict | None,
    "ip_intel":        dict | None,
    "mitre":           list[str],
    "evidence_summary": str          # 3-5 sentence analyst narrative
}
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import nemoclaw

_THREAT_INTEL_PATH = os.path.join(os.path.dirname(__file__), "..", "mock_data", "threat_intel.json")

_SYSTEM_PROMPT = """You are a forensic analyst writing an evidence brief for a SOC incident.
Given structured forensic data in JSON, output ONLY a valid JSON object with one field:
- evidence_summary: a 3-5 sentence analyst narrative covering what the malware did,
  how it persists, what the C2 infrastructure looks like, and the immediate containment priority.
Be specific — reference the actual process names, IPs, and malware family from the data.
Output ONLY the JSON object. No markdown, no explanation."""


def _load_threat_intel() -> dict:
    with open(_THREAT_INTEL_PATH) as f:
        return json.load(f)


def _build_process_tree(alert: dict) -> list[dict]:
    proc = alert.get("process", {})
    return [
        {
            "pid": alert.get("process", {}).get("parent_pid"),
            "name": proc.get("parent_name"),
            "role": "parent",
        },
        {
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "path": proc.get("path"),
            "command_line": proc.get("command_line"),
            "signed": proc.get("signed"),
            "sha256": proc.get("sha256"),
            "role": "child (suspicious)",
        },
    ]


def _extract_iocs(alert: dict) -> list[dict]:
    iocs = []

    proc = alert.get("process", {})
    if proc.get("sha256"):
        iocs.append({"type": "hash", "value": proc["sha256"], "context": proc.get("name")})

    for conn in alert.get("network", {}).get("outbound_connections", []):
        iocs.append({
            "type": "ip",
            "value": conn["dst_ip"],
            "context": f"port {conn['dst_port']} / {conn['protocol']}",
        })

    for fe in alert.get("file_events", []):
        iocs.append({"type": "file_path", "value": fe["path"], "context": fe["action"]})

    for re in alert.get("registry_events", []):
        iocs.append({
            "type": "registry_key",
            "value": re["key"],
            "context": f"{re['action']} → {re.get('data', '')}",
        })

    return iocs


def run(inputs: dict) -> dict:
    alert = inputs["alert"]
    triage = inputs["triage"]
    alert_id = alert.get("alert_id", "UNKNOWN")

    intel = _load_threat_intel()
    process_tree = _build_process_tree(alert)
    iocs = _extract_iocs(alert)

    file_hash = alert.get("process", {}).get("sha256")
    hash_intel = intel["hashes"].get(file_hash) if file_hash else None

    suspicious_ips = [
        ioc["value"] for ioc in iocs if ioc["type"] == "ip"
    ]
    ip_intel = intel["ips"].get(suspicious_ips[0]) if suspicious_ips else None

    forensic_data = {
        "alert_id": alert_id,
        "triage_severity": triage["severity"],
        "triage_classification": triage["classification"],
        "hostname": alert.get("hostname"),
        "username": alert.get("username"),
        "process_tree": process_tree,
        "iocs": iocs,
        "hash_intel": hash_intel,
        "ip_intel": ip_intel,
        "mitre": triage.get("mitre", []),
    }

    user_prompt = f"Produce an evidence summary for this forensic packet:\n{json.dumps(forensic_data, indent=2)}"
    result = nemoclaw.infer_json(_SYSTEM_PROMPT, user_prompt)

    return {
        "alert_id": alert_id,
        "process_tree": process_tree,
        "iocs": iocs,
        "hash_intel": hash_intel,
        "ip_intel": ip_intel,
        "mitre": forensic_data["mitre"],
        "evidence_summary": result["evidence_summary"],
    }


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    alert_path = os.path.join(os.path.dirname(__file__), "..", "mock_data", "edr_alert.json")
    with open(alert_path) as f:
        alert = json.load(f)

    # Simulate triage output
    mock_triage = {
        "alert_id": alert["alert_id"],
        "severity": "critical",
        "classification": "Phishing-delivered RAT with C2 beacon",
        "confidence": 0.97,
        "duplicate": False,
        "summary": "Outlook spawned a suspicious unsigned executable that beaconed to a known C2 IP.",
        "mitre": alert["mitre_techniques"],
    }

    output = run({"alert": alert, "triage": mock_triage})
    print(json.dumps(output, indent=2))
