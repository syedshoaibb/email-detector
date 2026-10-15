"""
SIH26106 - Email Threat Detection (FastAPI app)

Run locally:   uvicorn api:app --reload
Production:    uvicorn api:app --host 0.0.0.0 --port $PORT
"""

import hashlib
import json
import os
from fastapi import Request
from fastapi.responses import HTMLResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
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

app = FastAPI(
    title="SIH26106 Email Threat Detection",
    description="AI email threat detection and forensic analysis",
    version="4.1.0",
)
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
    limiter = Limiter(key_func=get_remote_address)

app.state.limiter = Limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)


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
        )

    def bullets(items):
        if not items:
            return '<div class="muted">None observed.</div>'
        return "<ul>" + "".join(f"<li>{escape(str(i))}</li>" for i in items) + "</ul>"

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    try:
        parsed_date = parsedate_to_datetime(msg.get("Date")).isoformat() if msg.get("Date") else None
    except Exception:
        parsed_date = None

    auth = forensic.get("authentication") or {}
    routing = forensic.get("routing") or {}
    urls = forensic.get("urls") or []
    attachments = forensic.get("attachments") or []
    timeline = forensic.get("timeline") or []
    findings = forensic.get("forensic_findings") or forensic.get("findings") or []
    rule_findings = (m1.get("rule_engine") or {}).get("findings") or []

    finding_html = []
    for item in findings:
        if isinstance(item, dict):
            fid = item.get("finding_id") or item.get("id") or item.get("rule_id") or "Finding"
            desc = item.get("description") or item.get("message") or item.get("title") or "Evidence observed."
            sev = item.get("severity") or "info"
        else:
            fid, desc, sev = "Finding", str(item), "info"
        finding_html.append(
            f'<div class="finding"><div class="finding-head"><b>{escape(str(fid))}</b>'
            f'<span class="badge badge-{escape(str(sev).lower())}">{escape(str(sev).upper())}</span></div>'
            f'<div>{escape(str(desc))}</div></div>'
        )

    if not finding_html:
        for item in rule_findings:
            finding_html.append(
                f'<div class="finding"><div class="finding-head"><b>{escape(str(item.get("rule_id", "Rule")))}</b>'
                f'<span class="badge badge-{escape(str(item.get("severity", "info")).lower())}">'
                f'{escape(str(item.get("severity", "info")).upper())}</span></div>'
                f'<div>{escape(str(item.get("description", "Content indicator observed.")))}</div></div>'
            )

    findings_html = "".join(finding_html) or '<div class="muted">No forensic findings reported.</div>'
    url_values = [json.dumps(u, ensure_ascii=False) if isinstance(u, dict) else str(u) for u in urls]

    attachment_values = []
    for item in attachments:
        if isinstance(item, dict):
            name = item.get("filename") or item.get("name") or "Attachment"
            typ = item.get("content_type") or item.get("type") or "Unknown type"
            size = item.get("size")
            suffix = f" — {size} bytes" if size is not None else ""
            attachment_values.append(f"{name} — {typ}{suffix}")
        else:
            attachment_values.append(str(item))

    timeline_values = [json.dumps(t, ensure_ascii=False) if isinstance(t, dict) else str(t) for t in timeline]
    auth_rows = list(auth.items()) if auth else [("Authentication", "Not observed")]
    routing_rows = list(routing.items()) if routing else [("Routing", "Not observed")]

    html = """<!doctype html>
<html><head><meta charset="utf-8"><title>Email Forensic Report</title>
<style>
body{margin:0;background:#f4f7fb;color:#172033;font:14px Arial,Segoe UI,sans-serif}.wrap{max-width:980px;margin:auto;padding:28px}
.header{background:#0f172a;color:#fff;border-radius:14px;padding:22px}.header h1{margin:0 0 6px;font-size:24px}.muted{color:#64748b}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-top:14px}
.metric{font-size:28px;font-weight:800;margin-top:6px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid #edf2f7;vertical-align:top}th{width:32%;color:#64748b;font-weight:600}
.badge{padding:3px 8px;border-radius:999px;font-size:10px;font-weight:700}.badge-high{background:#fee2e2;color:#991b1b}.badge-medium{background:#fef3c7;color:#92400e}.badge-low{background:#dcfce7;color:#166534}.badge-info{background:#e2e8f0;color:#334155}
.finding{border:1px solid #e2e8f0;border-radius:9px;padding:11px;margin:8px 0}.finding-head{display:flex;justify-content:space-between;margin-bottom:5px}ul{margin:8px 0 0 20px;padding:0}li{margin:5px 0;word-break:break-word}
@media(max-width:740px){.grid{grid-template-columns:1fr}.wrap{padding:16px}}
</style></head><body><div class="wrap">
<div class="header"><h1>Email Forensic Report</h1><div>__FILENAME__</div><div style="color:#cbd5e1;margin-top:8px">Evidence generated only from the submitted .eml.</div></div>
<div class="grid"><div class="card"><div class="muted">Threat probability</div><div class="metric">__THREAT__%</div><div>Verdict: <b>__VERDICT__</b></div></div><div class="card"><div class="muted">Safe probability</div><div class="metric">__SAFE__%</div><div>Model confidence: <b>__CONF__%</b></div></div></div>
<div class="card"><h2>Case & Message</h2><table>__MESSAGE_ROWS__</table></div>
<div class="grid"><div class="card"><h2>Authentication</h2><table>__AUTH_ROWS__</table></div><div class="card"><h2>Routing</h2><table>__ROUTING_ROWS__</table></div></div>
<div class="grid"><div class="card"><h2>URLs</h2><div class="muted">__URL_COUNT__ observed</div>__URLS__</div><div class="card"><h2>Attachments</h2><div class="muted">__ATTACH_COUNT__ observed</div>__ATTACHMENTS__</div></div>
<div class="card"><h2>Forensic Findings</h2>__FINDINGS__</div><div class="card"><h2>Timeline</h2>__TIMELINE__</div>
<div class="card"><h2>Evidence Scope</h2><div class="muted">Only observed and parsed evidence from the uploaded message is included. Missing fields are not fabricated.</div></div>
</div></body></html>"""

    return (html
        .replace("__FILENAME__", escape(filename))
        .replace("__THREAT__", f"{summary.get('final_threat_probability',0):.2f}")
        .replace("__SAFE__", f"{summary.get('safe_probability',0):.2f}")
        .replace("__CONF__", f"{summary.get('model_confidence',0):.2f}")
        .replace("__VERDICT__", escape(str(summary.get('verdict','UNKNOWN'))))
        .replace("__MESSAGE_ROWS__", rows([
            ("File", filename), ("SHA-256", sha256), ("From", msg.get("From")), ("To", msg.get("To")),
            ("Subject", msg.get("Subject")), ("Date header", msg.get("Date")), ("Parsed date", parsed_date),
            ("Message-ID", msg.get("Message-ID")), ("Reply-To", msg.get("Reply-To")), ("Return-Path", msg.get("Return-Path"))
        ]))
        .replace("__AUTH_ROWS__", rows(auth_rows))
        .replace("__ROUTING_ROWS__", rows(routing_rows))
        .replace("__URL_COUNT__", str(len(url_values))).replace("__URLS__", bullets(url_values))
        .replace("__ATTACH_COUNT__", str(len(attachment_values))).replace("__ATTACHMENTS__", bullets(attachment_values))
        .replace("__FINDINGS__", findings_html).replace("__TIMELINE__", bullets(timeline_values))
    )


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "system": "SIH26106 Email Threat Detection",
        "header_model": True,
        "text_model": m1_detector.text_model_available(),
        "forensics": "m2_forensics" if m2_analyze_email else "forensics_lite",
    }


@app.get("/")
def home():
    if not INDEX_FILE.is_file():
        raise HTTPException(
            status_code=500,
            detail=f"Homepage file not found: {INDEX_FILE}"
        )

    return FileResponse(
        path=str(INDEX_FILE),
        media_type="text/html"
    )


@app.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze_endpoint(
    request: Request,
    file: UploadFile = File(...)
):

    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    file_bytes = await file.read(MAX_UPLOAD_BYTES + 1)

    if not file_bytes:
        raise HTTPException(status_code=400, detail="The uploaded .eml file is empty.")

    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (10 MB maximum).")

    try:
        m1_result = analyze_eml_bytes(file_bytes)
        forensic_result = run_forensics(file_bytes)

        response = {
            "status": "success",
            "file": {"filename": filename, "size_bytes": len(file_bytes)},
            "summary": build_summary(m1_result, forensic_result),
            "m1": m1_result,
            "forensics": forensic_result,
            "report_html": build_lean_forensic_report(
                file_bytes, filename, m1_result, forensic_result
            ),
        }

        return JSONResponse(content=json_safe(response))

    except HTTPException:
        raise

    except Exception:
        import logging
        logging.exception("Email analysis failed")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please try again later."
        )

from pathlib import Path
from starlette.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

if not STATIC_DIR.is_dir():
    raise RuntimeError(f"Required static directory missing: {STATIC_DIR}")

@app.get("/terms", include_in_schema=False)
async def terms_page():
    return FileResponse(str(STATIC_DIR / "terms.html"))


@app.get("/privacy", include_in_schema=False)
async def privacy_page():
    return FileResponse(str(STATIC_DIR / "privacy.html"))


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(
    request: Request,
    exc: StarletteHTTPException
):
    if exc.status_code == 404:
        # Keep API errors in JSON format.
        if request.url.path.startswith("/api/"):
            return JSONResponse(
                status_code=404,
                content={"detail": "API endpoint not found"}
            )

        page = STATIC_DIR / "404.html"
        if page.is_file():
            return FileResponse(
                str(page),
                status_code=404,
                media_type="text/html"
            )

    # Preserve normal handling for other HTTP errors.
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
    )
