# test_local_models.py
import joblib

print("Testing modelparameters2.pkl...")
try:
    data = joblib.load("modelparameters2.pkl")
    print(f"✓ Loaded successfully: {type(data)}")
    if hasattr(data, "named_steps"):
        print(f"  Pipeline steps: {list(data.named_steps.keys())}")
except Exception as e:
    print(f"✗ Error: {e}")

print("\nTesting phishing_model.pkl...")
try:
    data = joblib.load("phishing_model.pkl")
    print(f"✓ Loaded successfully: {type(data)}")
    if isinstance(data, dict):
        print(f"  Keys: {list(data.keys())}")
        # Check if TF-IDF is fitted
        if "tfidf_subject" in data and hasattr(data["tfidf_subject"], "vocabulary_"):
            print(f"  ✓ TF-IDF is fitted (vocab size: {len(data['tfidf_subject'].vocabulary_)})")
        else:
            print(f"  ✗ TF-IDF is NOT fitted!")
except Exception as e:
    print(f"✗ Error: {e}")