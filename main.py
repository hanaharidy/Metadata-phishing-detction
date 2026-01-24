# main.py
import os
import io
import re
import uvicorn
import json
from typing import Union, Dict
import pandas as pd
from fastapi import FastAPI, HTTPException, Form, UploadFile, File, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# ==================== RAILWAY DEPLOYMENT ====================
# Download models from Google Drive before loading evaluator
from download_models import download_models

print("🚀 Starting Phishing Detection API...")
print("📦 Downloading model files from Google Drive...")
download_models()
print("✅ Models ready! Initializing application...")
# ============================================================

# -------------------- Load environment --------------------
load_dotenv()

# -------------------- FastAPI App --------------------
app = FastAPI(
    title="Ensemble Phishing Detection API",
    description="AI-powered phishing detection with dual model ensemble evaluation",
    version="2.0.0"
)

# -------------------- API Key --------------------
API_KEY = os.getenv("API_KEY", "your-secret-api-key-change-this")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")
    return api_key

# -------------------- CORS --------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Evaluator --------------------
# Import after models are downloaded
from Defense_Scripts.phishing_evaluator import PhishingEvaluator
evaluator = PhishingEvaluator(threshold=0.6)

# -------------------- Data Model --------------------
class EmailInput(BaseModel):
    subject: str
    sender: str
    body: str
    emaiheader: Union[str, Dict, None] = None
    ip: str
    targetemail: str

# -------------------- Helper --------------------
def clean_html(content: str) -> str:
    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        soup = BeautifulSoup(content, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text(separator=" ")
    return re.sub(r"\s+", " ", text).strip()

# ==================== ROUTES ====================

@app.get("/", response_class=HTMLResponse)
def health_check():
    return """
    <html>
    <head>
        <title>Phishing Detection API</title>
        <style>
            body {font-family:'Segoe UI', sans-serif; background: linear-gradient(120deg,#667eea,#764ba2); margin:0; padding:0; min-height:100vh; display:flex; justify-content:center; align-items:center;}
            .container {max-width:600px; background:#fff; padding:40px; border-radius:15px; box-shadow:0 10px 30px rgba(0,0,0,0.3);}
            h1 {text-align:center; color:#333; margin-bottom:10px;}
            .version {text-align:center; color:#666; font-size:14px; margin-bottom:30px;}
            .button {display:block; width:100%; background:#667eea; color:#fff; padding:12px; text-align:center; text-decoration:none; border-radius:8px; font-size:16px; margin:10px 0; transition:.3s;}
            .button:hover {background:#764ba2;}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Phishing Detection API</h1>
            <div class="version">Version 2.0.0 | Dual Model Ensemble</div>
            <a class="button" href="/predict_form">📧 Test Email Detection (Web Form)</a>
            <a class="button" href="/docs">📖 API Documentation (Swagger)</a>
        </div>
    </body>
    </html>
    """

# -------------------- API Prediction --------------------
@app.post("/predict")
def predict_email(data: EmailInput):
    try:
        cleaned_body = clean_html(data.body)

        result = evaluator.classify_single_email(
            subject=data.subject,
            sender=data.sender,
            body=cleaned_body,
            header=data.emaiheader,
            ip=data.ip,
            targetemail=data.targetemail
        )

        return {
            "success": True,
            "email": {
                "subject": data.subject,
                "sender": data.sender,
                "cleaned_body": cleaned_body
            },
            "analysis": result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------- Web Form (UNCHANGED UI) --------------------
@app.get("/predict_form", response_class=HTMLResponse)
def predict_form():
    return """
    <html>
    <head>
        <title>Phishing Email Prediction Form</title>
        <style>
            body {font-family:'Segoe UI', sans-serif; background:linear-gradient(120deg,#667eea,#764ba2); margin:0; padding:20px; min-height:100vh;}
            .container {max-width:700px; margin:0 auto; background:#fff; padding:30px 40px; border-radius:15px; box-shadow:0 10px 30px rgba(0,0,0,0.3);}
            h2 {text-align:center; color:#333; margin-bottom:30px;}
            label {display:block; margin-bottom:8px; font-weight:bold; color:#555;}
            input[type=text], textarea {width:100%; padding:12px 15px; margin-bottom:20px; border-radius:8px; border:1px solid #ccc; font-size:16px;}
            .button {background:#667eea; color:#fff; padding:12px 25px; border:none; border-radius:8px; font-size:18px; cursor:pointer; width:100%;}
            .button:hover {background:#764ba2;}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔍 Phishing Email Detector</h2>
            <form action="/predict_form" method="post">
                <label>Subject:</label>
                <input type="text" name="subject" required>

                <label>Sender:</label>
                <input type="text" name="sender" required>

                <label>Body:</label>
                <textarea name="body" rows="10" required></textarea>

                <label>Email Header (JSON):</label>
                <textarea name="emaiheader"></textarea>

                <label>IP Address:</label>
                <input type="text" name="ip">

                <label>Target Email:</label>
                <input type="text" name="targetemail">

                <input class="button" type="submit" value="🛡️ Analyze Email">
            </form>
        </div>
    </body>
    </html>
    """

# -------------------- Form POST --------------------
@app.post("/predict_form", response_class=HTMLResponse)
def predict_form_post(
    subject: str = Form(...),
    sender: str = Form(...),
    body: str = Form(...),
    emaiheader: str = Form(None),
    ip: str = Form(None),
    targetemail: str = Form(None)
):
    try:
        header_dict = json.loads(emaiheader) if emaiheader else {}
        cleaned_body = clean_html(body)

        result = evaluator.classify_single_email(
            subject=subject,
            sender=sender,
            body=cleaned_body,
            header=header_dict,
            ip=ip,
            targetemail=targetemail
        )

        color = "#e74c3c" if result["result"] == "PHISHING" else "#27ae60"
        emoji = "⚠️" if result["result"] == "PHISHING" else "✅"

        return f"""
        <div style="color:{color}; padding:20px; border:2px solid {color}; border-radius:10px;">
            <h3>{emoji} {result["result"]}</h3>
            <pre>{json.dumps(result, indent=2)}</pre>
            <a href="/predict_form">Try Again</a>
        </div>
        """

    except Exception as e:
        return f"<p style='color:red'>Error: {e}</p>"

# -------------------- Batch --------------------
@app.post("/predict-batch")
async def predict_batch(
    email_file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key)
):
    try:
        contents = await email_file.read()
        df = pd.read_excel(io.BytesIO(contents))

        results = []
        for _, row in df.iterrows():
            cleaned_body = clean_html(str(row["body"]))
            result = evaluator.classify_single_email(
                subject=str(row["subject"]),
                sender=str(row["sender"]),
                body=cleaned_body,
                header=None,
                ip=None,
                targetemail=None
            )
            results.append({**row.to_dict(), **result})

        return {"success": True, "data": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------- Run --------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))