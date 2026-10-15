"""
SIH26106 - Email Threat Detection (FastAPI app)

Run locally:   uvicorn api:app --reload
Production:    uvicorn api:app --host 0.0.0.0 --port $PORT
"""

import hashlib
import json
import os
from fastapi import Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html import escape

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import m1_detector
from m1_detector import analyze_eml_bytes
from forensics_lite import analyze_email_lite

# Optional: your teammate's full M2 module. If it is not installed (or fails),
# the built-in forensics_lite analyzer is used instead.
try:
    from m2_forensics.forensics import analyze_email as m2_analyze_email
except ImportError:
    m2_analyze_email = None

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
SAMPLE_FILE = STATIC_DIR / "sample.eml"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SIH26106 Email Threat Detection",
    description="AI email threat detection and forensic analysis",
    version="4.1.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


def to_dict(value):
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    try:
        return dict(value)
    except Exception:
        return {}


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if hasattr(value, "model_dump"):
        return json_safe(value.model_dump())
    if hasattr(value, "dict"):
        return json_safe(value.dict())
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def run_forensics(file_bytes):
    if m2_analyze_email is not None:
        try:
            return to_dict(m2_analyze_email(file_bytes))
        except Exception as exc:
            print("[warn] m2_forensics failed, using forensics_lite:", repr(exc))
    return analyze_email_lite(file_bytes)


def build_summary(m1, forensic):
    m1_result = m1.get("m1_result") or {}
    header = m1.get("header_model") or {}
    text = m1.get("text_model")          # None when the text model is not loaded
    rules = m1.get("rule_engine") or {}

    final_probability = float(m1_result.get("final_percentage", 0.0))
    header_probability = float(header.get("class_1_probability", 0.0)) * 100.0
    rule_probability = float(rules.get("rule_score", 0.0))

    def conf(p):
        return max(p / 100.0, 1.0 - p / 100.0)

    confidences = [conf(header_probability)]
    text_probability = None

    if text:
        text_probability = float(text.get("class_1_probability", 0.0)) * 100.0
        confidences.append(conf(text_probability))

    findings = forensic.get("forensic_findings", forensic.get("findings", []))

    return {
        "verdict": m1_result.get("verdict", "UNKNOWN"),
        "final_threat_probability": round(final_probability, 2),
        "safe_probability": round(max(0.0, 100.0 - final_probability), 2),
        "model_confidence": round(sum(confidences) / len(confidences) * 100.0, 2),
        "header_probability": round(header_probability, 2),
        "text_probability": None if text_probability is None else round(text_probability, 2),
        "rule_probability": round(rule_probability, 2),
        "text_model_used": text is not None,
        "rule_findings_count": len(rules.get("findings", [])),
        "forensic_findings_count": len(findings),
        "url_count": len(forensic.get("urls", [])),
        "attachment_count": len(forensic.get("attachments", [])),
        "timeline_events": len(forensic.get("timeline", [])),
    }


def build_lean_forensic_report(file_bytes, filename, m1_result, forensic_result):
    """Generate a compact evidence report from the submitted .eml only."""
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    forensic = forensic_result or {}
    m1 = m1_result or {}
    summary = build_summary(m1, forensic)

    def text(v, fallback="Not observed"):
        return fallback if v is None or v == "" else str(v)

    def rows(items):
        return "".join(
            f"<tr><th>{escape(str(k))}</th><td>{escape(text(v))}</td></tr>"
            for k, v in items
