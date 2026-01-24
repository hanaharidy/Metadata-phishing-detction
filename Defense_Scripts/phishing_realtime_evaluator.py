class PhishingEvaluator:
    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold
        self.model1 = None
        self.model2 = None

    def _load_models(self):
        if self.model1 is None:
            from test1 import predict_model1
            from test2 import predict_model2
            self.model1 = predict_model1
            self.model2 = predict_model2

    def classify_single_email(self, subject: str, sender: str, body: str) -> dict:
        self._load_models()

        score1 = float(self.model1(subject, sender, body))
        score2 = float(self.model2(subject, sender, body))
        max_score = max(score1, score2)

        return {
            "phishing_score_model1": round(score1, 3),
            "phishing_score_model2": round(score2, 3),
            "max_phishing_score": round(max_score, 3),
            "result": "PHISHING" if max_score >= self.threshold else "SAFE"
        }
