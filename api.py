"""
SIH26106 - Email Threat Detection (FastAPI app)

Run locally: uvicorn api:app --reload
Production:   uvicorn api:app --host 0.0.0.0 --port $PORT
"""

import json
import logging
from email import policy
from email.parser import BytesParser
from html import escape
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException

import m1_detector
from m1_detector import analyze_eml_bytes
from forensics_lite import analyze_email_lite

# Optional full forensic module. If unavailable or it fails, use the lite analyzer.
try:
    from m2_forensics.forensics import analyze_email as m2_analyze_email
except ImportError:
    m2_analyze_email = None

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
SAMPLE_FILE = STATIC_DIR / "sample.eml"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB
ALLOWED_EXTENSION = ".eml"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email-threat-api")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="SIH26106 Email Threat Detection",
    description="AI email threat detection and forensic analysis",
    version="4.2.0",
)

@app.get("/privacy")
def privacy_page():
    return FileResponse(STATIC_DIR / "privacy.html")

@app.get("/terms")
def terms_page():
    return FileResponse(STATIC_DIR / "terms.html")
    
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Serve only the project's static directory; uploaded email files are never saved.
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def to_dict(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        result = value.model_dump()
        return result if isinstance(result, dict) else {}
    if hasattr(value, "dict"):
        result = value.dict()
        return result if isinstance(result, dict) else {}
    try:
        result = dict(value)
        return result if isinstance(result, dict) else {}
    except (TypeError, ValueError):
        return {}


def json_safe(value: Any) -> Any:
    """Convert model/analyzer results to JSON-serializable values."""
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if hasattr(value, "model_dump"):
        return json_safe(value.model_dump())
    if hasattr(value, "dict"):
        return json_safe(value.dict())
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def run_forensics(file_bytes: bytes) -> dict:
    if m2_analyze_email is not None:
        try:
            result = to_dict(m2_analyze_email(file_bytes))
            if result:
                return result
        except Exception:
            # Do not return internal exception details to the caller.
            logger.exception("Full forensic module failed; using lite analyzer")
    try:
        return to_dict(analyze_email_lite(file_bytes))
    except Exception:
        logger.exception("Lite forensic analyzer failed")
        raise HTTPException(
            status_code=500,
            detail="Forensic analysis failed. Please try another .eml file.",
        )


def _float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        if number != number or number in (float("inf"), float("-inf")):
            return default
        return number
    except (TypeError, ValueError):
        return default


def _clamp_percent(value: Any) -> float:
    return max(0.0, min(100.0, _float(value)))


def build_summary(m1: dict, forensic: dict) -> dict:
    m1_result = to_dict(m1.get("m1_result"))
    header = to_dict(m1.get("header_model"))
    text_model = m1.get("text_model")
    text_model = to_dict(text_model) if text_model else None
    rules = to_dict(m1.get("rule_engine"))

    final_probability = _clamp_percent(m1_result.get("final_percentage", 0.0))
    header_probability = _clamp_percent(_float(header.get("class_1_probability", 0.0)) * 100.0)
    rule_probability = _clamp_percent(rules.get("rule_score", 0.0))

    def confidence(p: float) -> float:
        return max(p / 100.0, 1.0 - p / 100.0)

    confidence_values = [confidence(header_probability)]
    text_probability = None
    if text_model is not None:
        text_probability = _clamp_percent(
            _float(text_model.get("class_1_probability", 0.0)) * 100.0
        )
        confidence_values.append(confidence(text_probability))

    findings = forensic.get("forensic_findings", forensic.get("findings", []))
    if not isinstance(findings, list):
        findings = []
    rule_findings = rules.get("findings", [])
    if not isinstance(rule_findings, list):
        rule_findings = []

    verdict = str(m1_result.get("verdict", "UNKNOWN")).upper()
    # Keep the frontend's three known verdict names where a probability is available.
    if verdict not in {"LOW_RISK", "SUSPICIOUS", "HIGH_RISK"}:
        verdict = "HIGH_RISK" if final_probability >= 75 else (
            "SUSPICIOUS" if final_probability >= 50 else "LOW_RISK"
        )

    return {
        "verdict": verdict,
        "final_threat_probability": round(final_probability, 2),
        "safe_probability": round(max(0.0, 100.0 - final_probability), 2),
        "model_confidence": round(sum(confidence_values) / len(confidence_values) * 100.0, 2),
        "header_probability": round(header_probability, 2),
        "text_probability": None if text_probability is None else round(text_probability, 2),
        "rule_probability": round(rule_probability, 2),
        "text_model_used": text_model is not None,
        "rule_findings_count": len(rule_findings),
        "forensic_findings_count": len(findings),
        "url_count": len(forensic.get("urls", [])) if isinstance(forensic.get("urls", []), list) else 0,
        "attachment_count": len(forensic.get("attachments", [])) if isinstance(forensic.get("attachments", []), list) else 0,
        "timeline_events": len(forensic.get("timeline", [])) if isinstance(forensic.get("timeline", []), list) else 0,
    }


def build_lean_forensic_report(
    file_bytes: bytes, filename: str, m1_result: dict, forensic_result: dict
) -> str:
    """Create a self-contained HTML evidence report; all email-derived values are escaped."""
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    m1 = to_dict(m1_result)
    forensic = to_dict(forensic_result)
    summary = build_summary(m1, forensic)

    def safe_text(value: Any, fallback: str = "Not observed") -> str:
        if value is None or value == "":
            return fallback
        if isinstance(value, (dict, list, tuple)):
            try:
                return json.dumps(json_safe(value), ensure_ascii=False)
            except (TypeError, ValueError):
                return str(value)
        return str(value)

    def rows(items) -> str:
        return "".join(
            f"<tr><th>{escape(str(key))}</th><td>{escape(safe_text(value))}</td></tr>"
            for key, value in items
        )

    email_details = [
        ("From", msg.get("From", "")),
        ("To", msg.get("To", "")),
        ("Subject", msg.get("Subject", "")),
        ("Date", msg.get("Date", "")),
        ("Message-ID", msg.get("Message-ID", "")),
        ("Submitted filename", filename),
    ]
    summary_details = [
        ("Verdict", summary["verdict"]),
        ("Threat probability", f'{summary["final_threat_probability"]:.2f}%'),
        ("Safe probability", f'{summary["safe_probability"]:.2f}%'),
        ("Model confidence (estimate)", f'{summary["model_confidence"]:.2f}%'),
        ("Header model probability", f'{summary["header_probability"]:.2f}%'),
        ("Wording model probability", "Not loaded" if summary["text_probability"] is None else f'{summary["text_probability"]:.2f}%'),
        ("Rule score", f'{summary["rule_probability"]:.2f}%'),
        ("URLs", summary["url_count"]),
        ("Attachments", summary["attachment_count"]),
        ("Timeline events", summary["timeline_events"]),
    ]

    forensic_findings = forensic.get("forensic_findings", forensic.get("findings", []))
    if not isinstance(forensic_findings, list):
        forensic_findings = []
    finding_rows = []
    for finding in forensic_findings[:200]:
        if isinstance(finding, dict):
            title = finding.get("description") or finding.get("message") or finding.get("title") or "Finding"
            detail = finding.get("details") or finding.get("source") or finding.get("evidence") or ""
            finding_rows.append(
                "<li><strong>" + escape(safe_text(title)) + "</strong>"
                + (": " + escape(safe_text(detail)) if detail else "") + "</li>"
            )
        else:
            finding_rows.append("<li>" + escape(safe_text(finding)) + "</li>")

    url_items = forensic.get("urls", [])
    if not isinstance(url_items, list):
        url_items = []
    url_html = "".join(f"<li>{escape(safe_text(item))}</li>" for item in url_items[:300]) or "<li>None extracted</li>"

    attachment_items = forensic.get("attachments", [])
    if not isinstance(attachment_items, list):
        attachment_items = []
    attachment_html = ""
    for item in attachment_items[:200]:
        if isinstance(item, dict):
            attachment_html += "<li>" + escape(safe_text(item.get("filename") or item.get("name") or "Attachment"))
            attachment_html += " — " + escape(safe_text(item.get("content_type") or item.get("type") or "unknown type"))
            if item.get("sha256"):
                attachment_html += " — SHA-256: " + escape(safe_text(item.get("sha256")))
            attachment_html += "</li>"
        else:
            attachment_html += "<li>" + escape(safe_text(item)) + "</li>"
    attachment_html = attachment_html or "<li>None extracted</li>"

    generated = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email Forensic Report</title>
<style>
body{{font:14px/1.5 Arial,sans-serif;color:#17212b;margin:28px}}
h1{{font-size:24px;margin-bottom:4px}} h2{{font-size:17px;margin-top:26px}}
.muted{{color:#526170}} table{{border-collapse:collapse;width:100%;table-layout:fixed}}
th,td{{text-align:left;vertical-align:top;border-bottom:1px solid #dbe2e8;padding:8px;overflow-wrap:anywhere}}
th{{width:28%;color:#33485a}} li{{margin:6px 0;overflow-wrap:anywhere}}
.notice{{padding:12px;border:1px solid #c9d6e2;background:#f4f8fb}}
@media print{{body{{margin:12mm}}}}
</style></head><body>
<h1>Email Forensic Report</h1>
<p class="muted">SIH26106 Email Threat Detection · Generated {escape(generated)}</p>
<div class="notice">This report records automated analysis of the submitted message. Results are indicators, not proof that an email is safe or malicious.</div>
<h2>Assessment summary</h2><table>{rows(summary_details)}</table>
<h2>Message metadata</h2><table>{rows(email_details)}</table>
<h2>Extracted URLs</h2><ul>{url_html}</ul>
<h2>Attachments</h2><ul>{attachment_html}</ul>
<h2>Forensic findings</h2><ul>{"".join(finding_rows) or "<li>No forensic findings recorded.</li>"}</ul>
</body></html>"""


@app.get("/", include_in_schema=False)
async def homepage():
    if not INDEX_FILE.is_file():
        raise HTTPException(status_code=503, detail="The web interface is not installed.")
    return FileResponse(INDEX_FILE, media_type="text/html")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "forensics": "m2_forensics" if m2_analyze_email is not None else "forensics_lite",
        "text_model": bool(getattr(m1_detector, "TEXT_MODEL", None)),
    }


@app.get("/health", include_in_schema=False)
async def health_alias():
    return await health()


@app.get("/terms", include_in_schema=False)
async def terms():
    return JSONResponse(
        {"detail": "Terms and Conditions page is not configured yet."},
        status_code=404,
    )


@app.get("/privacy", include_in_schema=False)
async def privacy():
    return JSONResponse(
        {"detail": "Privacy Policy page is not configured yet."},
        status_code=404,
    )


@app.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze_email(request: Request, file: UploadFile = File(...)):
    # Never trust a client-provided filename as a filesystem path.
    original_name = file.filename or "uploaded.eml"
    filename = original_name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not filename or not filename.lower().endswith(ALLOWED_EXTENSION):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    try:
        # Read one byte over the limit to reject oversized uploads without loading
        # an arbitrarily large file into memory.
        file_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()

    if not file_bytes:
        raise HTTPException(status_code=400, detail="The uploaded .eml file is empty.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File is too large. Maximum size is 10 MB.")

    try:
        # Parse once to reject malformed input that cannot be interpreted as an email.
        BytesParser(policy=policy.default).parsebytes(file_bytes)
        m1 = to_dict(analyze_eml_bytes(file_bytes))
        forensic = run_forensics(file_bytes)
        summary = build_summary(m1, forensic)
        report_html = build_lean_forensic_report(file_bytes, filename, m1, forensic)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Email analysis failed")
        raise HTTPException(
            status_code=500,
            detail="Email analysis failed. Please check the file and try again.",
        )

    email_details = m1.get("email")
    if not isinstance(email_details, dict):
        email_details = {}

    return JSONResponse(
        content=json_safe({
            "file": {"filename": filename, "size_bytes": len(file_bytes)},
            "summary": summary,
            "m1": m1,
            "forensics": forensic,
            "report_html": report_html,
        }),
        headers={"Cache-Control": "no-store"},
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Keep API errors JSON for the frontend; avoid exposing internal paths or traces.
    if request.url.path.startswith("/api/") or request.url.path == "/health":
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if exc.status_code == 404 and request.url.path == "/":
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    # A missing favicon should not produce a noisy server traceback.
    raise HTTPException(status_code=404, detail="Not Found")
