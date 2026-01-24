import pandas as pd
from Defense_Scripts.defense_model1 import PhishingDefenseSystem
from Defense_Scripts.defense_model2 import EmailClassifier

print("Retraining Model 1...")
df = pd.read_excel("train_data.xlsx")
system = PhishingDefenseSystem()
df = system.preprocess(df)
X = system.fit_transform(df)
system.model.fit(X, df["label"])
system.save_model("phishing_model.pkl")
print("✅ Model 1 done")

print("Retraining Model 2...")
clf = EmailClassifier(max_iter=500)
X_train, X_test, y_train, y_test = clf.load_data("train_data.xlsx")
clf.train(X_train, y_train)
clf.save_model("modelparameters2.pkl")
print("✅ Model 2 done")
print("✅ DONE! Re-upload to Google Drive")
