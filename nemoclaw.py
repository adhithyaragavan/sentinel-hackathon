"""
NemoClaw Privacy Router — thin wrapper that routes all inference to
cloud-hosted Nemotron via NVIDIA NIM (build.nvidia.com).
No local GPU. No PII leaves the host unencrypted.
"""

import os
import json
from openai import OpenAI

_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
_DEFAULT_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        if not api_key:
            raise RuntimeError("NVIDIA_NIM_API_KEY not set in environment")
        _client = OpenAI(base_url=_NIM_BASE_URL, api_key=api_key)
    return _client


def infer(system_prompt: str, user_prompt: str, model: str = _DEFAULT_MODEL) -> str:
    """Send a prompt through the Privacy Router to NIM and return the response text."""
    client = _get_client()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
        max_tokens=1024,
    )
    return response.choices[0].message.content.strip()


def infer_json(system_prompt: str, user_prompt: str, model: str = _DEFAULT_MODEL) -> dict:
    """Like infer() but parses and returns the JSON object from the response."""
    raw = infer(system_prompt, user_prompt, model)
    # Strip markdown fences if the model wrapped the JSON
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())
