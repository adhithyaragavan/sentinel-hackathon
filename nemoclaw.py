"""
NemoClaw Privacy Router — thin wrapper that routes all inference to
cloud-hosted Nemotron via NVIDIA NIM (build.nvidia.com).
No local GPU. No PII leaves the host unencrypted.
"""

import os
import json
from openai import OpenAI

_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
# Hackathon-recommended default for agentic reasoning + tool calling.
# Upgrade to nvidia/nemotron-3-super-120b-a12b only if quality outweighs latency.
_DEFAULT_MODEL = "nvidia/nemotron-3-nano-30b-a3b"

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        if not api_key:
            raise RuntimeError("NVIDIA_NIM_API_KEY not set in environment")
        _client = OpenAI(base_url=_NIM_BASE_URL, api_key=api_key)
    return _client


# Nemotron is a reasoning model — it spends tokens on internal reasoning before
# emitting the answer, so the budget must cover reasoning + the full JSON payload.
# Too low and the JSON gets truncated mid-structure.
_MAX_TOKENS = 4096


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
        max_tokens=_MAX_TOKENS,
    )
    return response.choices[0].message.content.strip()


def _extract_json(raw: str) -> str:
    """Pull a JSON object out of a model response that may include reasoning
    traces (<think>...</think>), markdown fences, or surrounding prose.
    Nemotron reasoning models sometimes emit these; be tolerant."""
    # Drop <think>...</think> reasoning blocks
    if "</think>" in raw:
        raw = raw.split("</think>")[-1]
    # Strip markdown fences
    if "```" in raw:
        # take the content of the first fenced block
        parts = raw.split("```")
        if len(parts) >= 2:
            candidate = parts[1]
            if candidate.lstrip().startswith("json"):
                candidate = candidate.lstrip()[4:]
            raw = candidate
    # Fall back to the outermost {...} span
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start : end + 1]
    return raw.strip()


def infer_json(system_prompt: str, user_prompt: str, model: str = _DEFAULT_MODEL) -> dict:
    """Like infer() but parses and returns the JSON object from the response.
    Retries once with a stricter instruction if the first parse fails."""
    raw = infer(system_prompt, user_prompt, model)
    try:
        return json.loads(_extract_json(raw))
    except json.JSONDecodeError:
        # One retry with an explicit reminder — cheap insurance for the live demo
        retry = infer(
            system_prompt,
            user_prompt + "\n\nReturn ONLY the raw JSON object. No reasoning, no prose, no markdown.",
            model,
        )
        return json.loads(_extract_json(retry))


def smoke_test() -> bool:
    """Verify NIM connectivity by listing models and doing a tiny completion.
    Returns True on success, raises on failure. Used by scripts/smoke_test.sh."""
    client = _get_client()

    models = client.models.list()
    model_ids = [m.id for m in models.data]
    print(f"NIM reachable — {len(model_ids)} models available")
    if _DEFAULT_MODEL in model_ids:
        print(f"Default model '{_DEFAULT_MODEL}' is available")
    else:
        print(f"WARNING: default model '{_DEFAULT_MODEL}' not in model list")

    reply = infer("You are a health check.", "Reply with the single word: OK")
    print(f"Inference OK — model replied: {reply!r}")
    return True


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    smoke_test()
