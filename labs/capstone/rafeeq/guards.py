"""Egress guard for Rafeeq, enforced in code (a before_tool hook): it does not depend on the model obeying.

Adapted from Lab 4.3 (labs/_src/D4_3_security.py). Differences: it fails closed when the harness has not set a
recipient, it also scans the subject, it matches link hosts exactly, and it logs every block.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ID_RE = re.compile(r"\b[12]\d{9}\b")                    # a 10-digit national ID / iqama number
MOBILE_RE = re.compile(r"(?:\+966|00966|0)?5\d{8}\b")    # a Saudi mobile number
LINK_RE = re.compile(r"https?://([^/\s)]+)")
ALLOWED_HOST = "madar.example"

# Set by the HARNESS, never by the model: the only address this conversation may email.
CONTEXT: dict = {"recipient": None}

BLOCK_LOG = Path(__file__).resolve().parents[2] / "artifacts" / "rafeeq" / "blocked.jsonl"


def _log(args: dict, reasons: list) -> None:
    BLOCK_LOG.parent.mkdir(parents=True, exist_ok=True)
    with BLOCK_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "to": str(args.get("to")),
                            "reasons": reasons}, ensure_ascii=False) + "\n")


def _bad_host(host: str) -> bool:
    host = host.lower()
    return not (host == ALLOWED_HOST or host.endswith("." + ALLOWED_HOST))


def egress_guard(name: str, args: dict):
    """before_tool hook: return a JSON error string to block the call, or None to let it run."""
    if name != "send_email":
        return None
    reasons = []
    allowed = (CONTEXT.get("recipient") or "").strip().lower()
    to = str(args.get("to", "")).strip().lower()
    text = str(args.get("subject", "")) + "\n" + str(args.get("body", ""))
    if not allowed:
        reasons.append("no recipient is authorised for this conversation")
    elif to != allowed:
        reasons.append("reply only to the authorised recipient")
    if ID_RE.search(text) or MOBILE_RE.search(text):
        reasons.append("no national IDs or mobile numbers in emails")
    if any(_bad_host(h) for h in LINK_RE.findall(text)):
        reasons.append("links only to madar.example")
    if reasons:
        _log(args, reasons)
        return json.dumps({"error": "Blocked by the egress policy: " + "; ".join(reasons)})
    return None
