import os
import pandas as pd
from Defense_Scripts.defense_model1 import PhishingDefenseSystem

# Use relative path that works both locally and in deployment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

# Initialize system globally
_system = None

def load_system():
    """Lazy load the model to avoid loading it multiple times"""
    global _system
    if _system is None:
        _system = PhishingDefenseSystem()
        _system.load_model(MODEL_PATH)
    return _system

def predict_from_excel(
    input_file: str,
    output_file: str,
    sheet_name: str = "Predictions",
    threshold: float = 0.5
):
    """Predict phishing from Excel file and save results"""
    system = load_system()
    df_test = pd.read_excel(input_file)

    df_test = system.preprocess(df_test)
    X_test = system.transform(df_test)

    df_test["phishing_score"] = system.model.predict_proba(X_test)[:, 1]
    df_test["predicted_label"] = (df_test["phishing_score"] >= threshold).astype(int)

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    with pd.ExcelWriter(output_file, engine="openpyxl", mode="w") as writer:
        df_test[["subject", "sender", "body", "phishing_score", "predicted_label"]].to_excel(
            writer, sheet_name=sheet_name, index=False
        )

    return output_file


def predict_single_email(
    subject: str,
    sender: str,
    body: str,
    threshold: float = 0.5
):
    """
    Predict phishing score and label for a single email.
    Can be imported and used anywhere (API, UI, CLI).
    """
    system = load_system()

    email_df = pd.DataFrame([{
        "subject": subject,
        "sender": sender,
        "body": body
    }])

    email_df = system.preprocess(email_df)
    X_email = system.transform(email_df)

    phishing_score = system.model.predict_proba(X_email)[0, 1]
    predicted_label = int(phishing_score >= threshold)

    return {
        "phishing_score": round(float(phishing_score), 4),
        "predicted_label": predicted_label,
        "prediction": "phishing" if predicted_label == 1 else "legitimate"
    }