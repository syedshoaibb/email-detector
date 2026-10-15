---
title: Email Threat Detection
emoji: 📧
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# SIH26106 – Email Threat Detection & Forensics

Upload a `.eml` file → XGBoost header model + content rules + forensic evidence.

## Run locally
```bash
pip install -r requirements.txt
uvicorn api:app --reload
# open http://127.0.0.1:8000
```
Try `sample/sus_email.eml`.

## Files
| File | Purpose |
|---|---|
| `api.py` | FastAPI server (`/`, `/api/analyze`, `/api/health`) |
| `static/index.html` | The web page |
| `m1_detector.py` | Header model + (optional) text model + rules, fused into one score |
| `m1_rules.py` | Content rule engine |
| `header_features.py` | Feature extraction – identical to training |
| `forensics_lite.py` | Auth / routing / URL / attachment / timeline forensics |
| `xgboost_header_model.pkl` | Trained header model |

## Optional: DistilRoBERTa text model
Put the model folder at `models/distilroberta_email_model/` and
`pip install -r requirements-text-model.txt`. It is detected automatically
(needs ~2 GB RAM). Without it the score uses header model + rules only.
