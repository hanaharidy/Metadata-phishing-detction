import os
import pandas as pd
from Defense_Scripts.defense_model2 import EmailClassifier

# Use relative path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_FILE = os.path.join(BASE_DIR, "modelparameters2.pkl")

# Initialize classifier globally
_classifier = None

def load_classifier():
    """Lazy load the model"""
    global _classifier
    if _classifier is None:
        _classifier = EmailClassifier()
        _classifier.load_model(MODEL_FILE)
    return _classifier

def predict_single_email(subject: str, sender: str, body: str, threshold: float = 0.5):
    """Predict phishing for single email"""
    classifier = load_classifier()
    
    # Use the predict_single method from EmailClassifier
    label, phishing_score = classifier.predict_single(sender, subject, body)
    
    # Handle None score
    if phishing_score is None:
        phishing_score = 0.0
    
    predicted_label = int(phishing_score >= threshold)
    
    return {
        "phishing_score": round(float(phishing_score), 4),
        "predicted_label": predicted_label,
        "prediction": "phishing" if predicted_label == 1 else "legitimate"
    }