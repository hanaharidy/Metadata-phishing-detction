# 🛡️ Phishing Detection API

> Real-time email phishing classifier using a **dual-model ensemble** served via REST API and an interactive web interface.

---

## What It Does

Analyzes emails by subject, sender, and body content to classify them as **PHISHING** or **LEGITIMATE** in real time. Two independent ML models score each email separately — the final verdict uses the **maximum phishing score** across both models to minimize false negatives (missed phishing attempts).

**Live demo:** *(add your deployment URL here if hosted)*

---

## Architecture

```
Email Input (subject + sender + body)
        │
        ▼
 HTML Cleaner (BeautifulSoup)       ← strips scripts, styles, normalizes whitespace
        │
        ▼
PhishingEvaluator (Ensemble)
   ├── Model 1 → phishing_score_1
   └── Model 2 → phishing_score_2
        │
        ▼
max(score_1, score_2) > 0.6 threshold
        │
        ▼
  PHISHING / LEGITIMATE
```

The ensemble approach using `max()` rather than averaging is intentional: it prioritizes recall over precision, which is the correct tradeoff for a security classifier where a missed phishing email is more costly than a false alarm.

---

## Results

| Metric | Value |
|--------|-------|
| Classification accuracy | **97%** |
| Decision threshold | 0.6 (tuned for recall) |
| Inference | Real-time via REST API |
| Input formats | Raw text, HTML email bodies |

---

## Tech Stack

- **API framework:** FastAPI
- **ML models:** Scikit-learn ensemble (dual-model)
- **Feature engineering:** TF-IDF embeddings + statistical metadata signals
- **HTML parsing:** BeautifulSoup + lxml
- **Deployment:** Docker + Procfile (cloud-ready)
- **Language:** Python 3

---

## API Endpoints

### `POST /predict`
Classify an email via JSON.

```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify your account",
    "sender": "security@suspicious-domain.com",
    "body": "Click here to confirm your password immediately..."
  }'
```

**Response:**
```json
{
  "subject": "Urgent: Verify your account",
  "sender": "security@suspicious-domain.com",
  "cleaned_body": "Click here to confirm your password immediately...",
  "result": "PHISHING",
  "phishing_score_model1": 0.89,
  "phishing_score_model2": 0.76,
  "max_phishing_score": 0.89
}
```

### `GET /predict_form`
Interactive web UI — paste an email and get instant results with visual score breakdowns.

### `GET /`
Landing page with API documentation links.

---

## Run Locally

```bash
# Clone the repo
git clone https://github.com/hanaharidy/phishing-detection-api-demo.git
cd phishing-detection-api-demo

# Install dependencies
pip install -r requirements.txt

# Start the API (models download automatically on first run)
uvicorn main:app --reload

# Open in browser
# http://localhost:8000
```

**Models are downloaded automatically on startup** via `download_models.py` — no manual setup needed.

---

## Run with Docker

```bash
docker build -t phishing-api .
docker run -p 8000:8000 phishing-api
```

---

## Project Structure

```
├── main.py                 # FastAPI app, routes, HTML UI
├── phishing_evaluator.py   # Dual-model ensemble logic
├── download_models.py      # Auto model download on startup
├── Defense_Scripts/        # Supporting detection scripts
├── requirements.txt
├── Procfile                # Cloud deployment config
└── runtime.txt
```

---

## Design Decisions

**Why two models?**
A single model can have blind spots for certain phishing patterns. Running two independent classifiers and taking the maximum score catches edge cases that one model alone would miss — at the cost of slightly more compute, which is acceptable for a security use case.

**Why max() instead of average?**
In phishing detection, false negatives (missed attacks) are more dangerous than false positives (flagging a legitimate email). `max()` is more aggressive in flagging suspicious emails, which is the correct tradeoff.

**Why 0.6 threshold instead of 0.5?**
Tuned on validation data to balance precision and recall. At 0.6 the classifier reaches 97% accuracy while maintaining acceptable false positive rates.

---

## Background

Built during an ML Engineering internship at Digital Fortress Egypt. The pipeline handles real-world email inputs including HTML-formatted bodies, mixed encodings, and adversarial obfuscation techniques common in phishing emails.

---

## Topics

`machine-learning` `fastapi` `cybersecurity` `phishing-detection` `nlp` `ensemble-learning` `python` `docker` `rest-api` `email-security`
