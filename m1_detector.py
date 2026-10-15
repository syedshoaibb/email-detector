"""
M1 - Email threat detection.

Three signals are fused into one score:
  1. XGBoost header model        (xgboost_header_model.pkl)
  2. DistilRoBERTa text model    (OPTIONAL - skipped if the model folder
                                  or torch/transformers are not available)
  3. Rule engine                 (content rules + header indicators)
"""

import html as html_lib
import os
import re
import warnings

import joblib
import numpy as np
import pandas as pd

from email import policy
from email.parser import BytesParser

from header_features import extract_features
from m1_rules import analyze_content

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HEADER_MODEL_PATH = os.getenv(
    "HEADER_MODEL_PATH",
    os.path.join(BASE_DIR, "xgboost_header_model.pkl"),
)

TEXT_MODEL_PATH = os.getenv(
    "TEXT_MODEL_PATH",
    os.path.join(BASE_DIR, "models", "distilroberta_email_model"),
)


# ============================================================
# LOAD HEADER MODEL (required)
# ============================================================

print("Loading XGBoost header model...")

header_package = joblib.load(HEADER_MODEL_PATH)
header_model = header_package["model"]
header_feature_names = header_package["feature_order"]

_classes = list(getattr(header_model, "classes_", [0, 1]))
SPAM_INDEX = _classes.index(1) if 1 in _classes else 1


# ============================================================
# LOAD TEXT MODEL (optional)
# ============================================================

tokenizer = None
text_model = None
torch = None
TEXT_MODEL_ERROR = None


def _load_text_model():
    global tokenizer, text_model, torch, TEXT_MODEL_ERROR

    if not os.path.isdir(TEXT_MODEL_PATH):
        TEXT_MODEL_ERROR = f"Text model folder not found: {TEXT_MODEL_PATH}"
        return

    try:
        import torch as _torch
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )

        print("Loading DistilRoBERTa...")

        tokenizer = AutoTokenizer.from_pretrained(TEXT_MODEL_PATH)
        text_model = AutoModelForSequenceClassification.from_pretrained(
            TEXT_MODEL_PATH
        )
        text_model.eval()
        torch = _torch

    except Exception as error:  # missing torch/transformers, bad files...
        text_model = None
        TEXT_MODEL_ERROR = f"Text model could not be loaded: {error}"


_load_text_model()

if text_model is None:
    print(f"[info] DistilRoBERTa disabled. {TEXT_MODEL_ERROR}")


def text_model_available():
    return text_model is not None


# ============================================================
# EMAIL PARSING
# ============================================================

def _strip_html(value):
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def parse_email_bytes(raw_bytes):
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    plain_parts = []
    html_parts = []

    for part in message.walk():

        if part.is_multipart():
            continue

        # Skip attachments - only read real message bodies
        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if not content:
            continue

        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    plain = "\n".join(plain_parts)
    html_raw = "\n".join(html_parts)

    return {
        "sender": str(message.get("From", "")),
        "receiver": str(message.get("To", "")),
        "date": str(message.get("Date", "")),
        "subject": str(message.get("Subject", "")),
        # Text for the language model: readable text only
        "body_text": (plain + "\n" + _strip_html(html_raw)).strip(),
        # Text for the rule engine: keep raw HTML so href URLs are visible
        "body_raw": (plain + "\n" + html_raw).strip(),
    }


# ============================================================
# HEADER MODEL
# ============================================================

def run_header_model(raw_text):
    """
    Uses the exact feature function used at training time.
    Returns the model result plus the raw feature dictionary.
    """

    features = extract_features(raw_text)

    frame = pd.DataFrame([features]).reindex(columns=header_feature_names)

    probability = float(header_model.predict_proba(frame)[0][SPAM_INDEX])

    return {
        "prediction": int(probability >= 0.50),
        "class_1_probability": round(probability, 4),
        "class_0_probability": round(1.0 - probability, 4),
    }, features


# ============================================================
# HEADER INDICATORS (deterministic, explainable)
# ============================================================
#
# The XGBoost model is trained on the SpamAssassin corpus (ham vs spam)
# and can under-react to modern phishing, so clear header red flags are
# also scored explicitly and shown to the user.

BAD_AUTH = {"fail", "softfail", "temperror", "permerror"}


def header_indicators(features):
    findings = []

    def add(rule_id, severity, description, matches=None):
        findings.append({
            "rule_id": rule_id,
            "category": "header",
            "severity": severity,
            "description": description,
            "matches": matches or [],
        })

    for rule_id, key, name in (
        ("H001", "spf_status", "SPF"),
        ("H002", "dkim_status", "DKIM"),
        ("H003", "dmarc_status", "DMARC"),
    ):
        if features.get(key) in BAD_AUTH:
            add(rule_id, "high", f"{name} authentication {features[key]}")

    if features.get("sender_replyto_mismatch"):
        add(
            "H004", "medium",
            "Reply-To domain differs from sender domain",
            [features["sender_domain"], features["reply_to_domain"]],
        )

    if features.get("sender_returnpath_mismatch"):
        add(
            "H005", "medium",
            "Return-Path domain differs from sender domain",
            [features["sender_domain"], features["return_path_domain"]],
        )

    if features.get("message_id_sender_mismatch"):
        add(
            "H006", "low",
            "Message-ID domain differs from sender domain",
            [features["sender_domain"], features["message_id_domain"]],
        )

    if features.get("received_count", 0) == 0:
        add("H007", "low", "No Received headers were found")

    if features.get("sender_domain_is_ip"):
        add("H008", "high", "Sender domain is a raw IP address")

    return findings


# ============================================================
# TEXT MODEL
# ============================================================

def run_text_model(subject, body):

    if text_model is None:
        return None

    combined_text = subject + "\n\n" + body

    inputs = tokenizer(
        combined_text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=128,
    )

    with torch.no_grad():
        outputs = text_model(**inputs)

    probabilities = torch.softmax(outputs.logits, dim=1)[0].cpu().numpy()

    return {
        "prediction": int(np.argmax(probabilities)),
        "class_0_probability": round(float(probabilities[0]), 4),
        "class_1_probability": round(float(probabilities[1]), 4),
    }


# ============================================================
# COMBINE RESULTS
# ============================================================

def combine_results(header_result, text_result, rule_result):

    # Weights (header / text / rules) = 30% / 50% / 20%.
    # If the text model is not loaded, the remaining weights are
    # re-normalised so the score still spans 0-100%.
    parts = [
        (0.30, header_result["class_1_probability"]),
        (0.20, min(rule_result["rule_score"], 100) / 100.0),
    ]

    notes = []

    if text_result is not None:
        parts.append((0.50, text_result["class_1_probability"]))
    else:
        notes.append(
            "Text model not loaded - score uses header model + rules only."
        )

    total_weight = sum(weight for weight, _ in parts)

    final_score = sum(weight * score for weight, score in parts) / total_weight

    final_score = max(0.0, min(1.0, final_score))

    if final_score >= 0.75:
        verdict = "HIGH_RISK"
    elif final_score >= 0.50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW_RISK"

    return {
        "final_score": round(final_score, 4),
        "final_percentage": round(final_score * 100, 2),
        "verdict": verdict,
        "text_model_used": text_result is not None,
        "notes": notes,
    }


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_eml_bytes(raw_bytes):

    raw_text = raw_bytes.decode("utf-8", errors="ignore")

    email_data = parse_email_bytes(raw_bytes)

    header_result, header_features = run_header_model(raw_text)

    text_result = run_text_model(
        email_data["subject"],
        email_data["body_text"],
    )

    rule_result = analyze_content(
        subject=email_data["subject"],
        body=email_data["body_raw"],
    )

    # Merge header indicators into the rule engine output
    h_findings = header_indicators(header_features)

    points = {"high": 20, "medium": 10, "low": 3}

    header_points = sum(points[f["severity"]] for f in h_findings)

    rule_result["findings"] = rule_result["findings"] + h_findings
    rule_result["content_score"] = rule_result["rule_score"]
    rule_result["header_indicator_score"] = min(header_points, 100)
    rule_result["rule_score"] = min(rule_result["rule_score"] + header_points, 100)
    rule_result["summary"] = (
        f"{len(rule_result['findings'])} indicator(s) detected."
        if rule_result["findings"]
        else "No major security indicator detected."
    )

    combined = combine_results(header_result, text_result, rule_result)

    return {
        "email": {
            "sender": email_data["sender"],
            "receiver": email_data["receiver"],
            "subject": email_data["subject"],
            "date": email_data["date"],
        },
        "header_model": header_result,
        "text_model": text_result,
        "rule_engine": rule_result,
        "m1_result": combined,
    }


def analyze_eml(eml_path):
    """File-path wrapper (used by the command line test)."""

    if not os.path.exists(eml_path):
        raise FileNotFoundError(f"Email file not found: {eml_path}")

    with open(eml_path, "rb") as file:
        return analyze_eml_bytes(file.read())


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python m1_detector.py your_email.eml")
        raise SystemExit(1)

    print(json.dumps(analyze_eml(sys.argv[1]), indent=2, ensure_ascii=False))
