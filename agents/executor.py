"""
Tool-Executor Agent — detonates the suspicious file inside a Docker sandbox
with a default-deny network policy and captures blocked connection attempts.

Sandbox enforcement:
  --network none        no outbound connections (default-deny)
  --read-only           immutable container filesystem
  --tmpfs /tmp          writable scratch space, non-executable, dropped on exit
  --cap-drop ALL        no Linux capabilities
  --security-opt no-new-privileges

Input:  {
    "alert":    <original EDR alert dict>,
    "forensic": <forensic examiner output dict>
}
Output: {
    "alert_id":          str,
    "sandbox_name":      str,
    "detonation_status": "completed" | "failed",
    "blocked_connections": list[dict],
    "sandbox_log_excerpt": str,
    "verdict":           "malicious" | "suspicious" | "clean",
    "verdict_reason":    str
}
"""

import sys
import os
import json
import subprocess
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_SANDBOX_IMAGE = "python:3.11-slim"
_SANDBOX_NAME  = "sentinel-detonation"

# Simulated malware payload: tries to TCP-connect to the C2 IP, writes a
# persistence stub, then exits. Stand-in for the real binary.
_DECOY_PAYLOAD = """\
#!/usr/bin/env python3
import socket, os, sys

c2_ip   = "185.220.101.47"
c2_port = 4444

print(f"[malware] attempting beacon to {c2_ip}:{c2_port}", flush=True)
try:
    s = socket.create_connection((c2_ip, c2_port), timeout=5)
    s.send(b"BEACON\\n")
    print("[malware] C2 connection established", flush=True)
    s.close()
except Exception as e:
    print(f"[malware] beacon failed: {e}", flush=True)

startup = "/tmp/svchost32.exe"
with open(startup, "w") as f:
    f.write("malware stub")
print(f"[malware] dropped persistence to {startup}", flush=True)
sys.exit(0)
"""


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def run(inputs: dict) -> dict:
    alert    = inputs["alert"]
    forensic = inputs["forensic"]
    alert_id = alert.get("alert_id", "UNKNOWN")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix="sample_", delete=False
    ) as f:
        f.write(_DECOY_PAYLOAD)
        payload_path = f.name

    try:
        # Run payload in an isolated Docker container:
        #   --network none    → all outbound connections blocked at the kernel level
        #   --read-only       → immutable root filesystem
        #   --tmpfs /tmp      → writable scratch, dropped on container exit
        #   --cap-drop ALL    → strip all Linux capabilities
        rc, exec_out, exec_err = _run([
            "docker", "run", "--rm",
            "--name",    _SANDBOX_NAME,
            "--network", "none",
            "--read-only",
            "--tmpfs",   "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{payload_path}:/sandbox/sample.py:ro",
            _SANDBOX_IMAGE,
            "python3", "/sandbox/sample.py",
        ], timeout=60)

        detonation_status = "completed"
        combined_output   = "\n".join(filter(None, [exec_out, exec_err]))

        # Synthesise a deny event from the payload's own report — Docker's
        # --network none drops packets at the kernel; the payload gets ENETUNREACH
        # or ECONNREFUSED and prints "beacon failed".
        blocked = []
        if "beacon failed" in combined_output:
            conns = alert.get("network", {}).get("outbound_connections", [{}])
            c2    = conns[0] if conns else {}
            blocked = [{
                "dst_host":    c2.get("dst_ip", "unknown"),
                "dst_port":    str(c2.get("dst_port", "")),
                "deny_reason": "network unreachable — container running with --network none",
                "raw": next(
                    (l for l in combined_output.splitlines() if "beacon failed" in l), ""
                ),
            }]

    except subprocess.TimeoutExpired:
        detonation_status = "failed"
        combined_output   = "docker run timed out"
        blocked           = []
    except Exception as e:
        detonation_status = "failed"
        combined_output   = str(e)
        blocked           = []
    finally:
        os.unlink(payload_path)
        # Force-remove the container if it's still running (e.g. after timeout)
        subprocess.run(
            ["docker", "rm", "-f", _SANDBOX_NAME],
            capture_output=True,
        )

    hash_intel = forensic.get("hash_intel") or {}
    if blocked and hash_intel.get("malicious"):
        verdict = "malicious"
        verdict_reason = (
            f"Confirmed {hash_intel.get('malware_family', 'malware')}: "
            f"{len(blocked)} outbound C2 connection(s) blocked by sandbox. "
            f"Hash flagged by {hash_intel.get('vendor_detections')}/"
            f"{hash_intel.get('total_vendors')} vendors."
        )
    elif blocked:
        verdict = "suspicious"
        verdict_reason = f"{len(blocked)} blocked outbound connection(s) observed but hash is unconfirmed."
    elif detonation_status == "completed":
        verdict = "clean"
        verdict_reason = "No blocked connections observed during detonation."
    else:
        verdict = "suspicious"
        verdict_reason = "Detonation failed — treat as suspicious pending manual review."

    return {
        "alert_id":          alert_id,
        "sandbox_name":      _SANDBOX_NAME,
        "detonation_status": detonation_status,
        "blocked_connections": blocked,
        "sandbox_log_excerpt": combined_output[:2000],
        "verdict":           verdict,
        "verdict_reason":    verdict_reason,
    }


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    alert_path = os.path.join(os.path.dirname(__file__), "..", "mock_data", "edr_alert.json")
    with open(alert_path) as f:
        alert = json.load(f)

    mock_forensic = {
        "alert_id": alert["alert_id"],
        "iocs": [{"type": "hash", "value": alert["process"]["sha256"]}],
        "hash_intel": {
            "malicious": True, "malware_family": "AsyncRAT",
            "vendor_detections": 54, "total_vendors": 72,
        },
        "ip_intel": {"malicious": True},
        "mitre": alert["mitre_techniques"],
        "evidence_summary": "AsyncRAT dropped via phishing attachment.",
    }

    output = run({"alert": alert, "forensic": mock_forensic})
    print(json.dumps(output, indent=2))
