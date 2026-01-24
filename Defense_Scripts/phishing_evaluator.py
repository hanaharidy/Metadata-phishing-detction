import pandas as pd
from typing import Union, Dict, Optional
from Defense_Scripts.test1 import predict_single_email as predict_model1
from Defense_Scripts.test2 import predict_single_email as predict_model2
from Defense_Scripts.ip_checker import VirusTotalIPChecker
from Defense_Scripts.sender_metadata_score import SenderChecker

class PhishingEvaluator:

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def classify_single_email(
        self,
        subject: str,
        sender: str,
        body: str,
        header: Union[str, Dict, None],
        ip: Optional[str],
        targetemail: Optional[str]
    ) -> dict:

        # Model predictions
        r1 = predict_model1(subject, sender, body, self.threshold)
        r2 = predict_model2(subject, sender, body, self.threshold)

        score1 = float(r1["phishing_score"])
        score2 = float(r2["phishing_score"])

        max_score = max(score1, score2)
        label = "PHISHING" if max_score >= self.threshold else "SAFE"

        # Sender check (safe serialization)
        try:
            sender_checker = SenderChecker(sender, header)
            sender_result = sender_checker.run() if hasattr(sender_checker, "run") else str(sender_checker)
        except Exception as e:
            sender_result = f"Sender check failed: {e}"

        # IP check
        try:
            ip_checker = VirusTotalIPChecker()
            ip_result = ip_checker.run_interactive(ip) if ip else "No IP provided"
        except Exception as e:
            ip_result = f"IP check failed: {e}"

        return {
            "Sender Checker": sender_result,
            "phishing_score_model1": round(score1, 4),
            "phishing_score_model2": round(score2, 4),
            "max_phishing_score": round(max_score, 4),
            "result": label,
            "IP Checker": ip_result,
            "Target Email Risk Score": 87
        }