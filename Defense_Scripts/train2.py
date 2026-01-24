import os
from datetime import datetime
from defense_model2 import EmailClassifier

train_file = r"C:\Users\DELL\Downloads\denv\denv\dataset\train_data.xlsx"

clf = EmailClassifier(max_iter=500)
X_train, X_test, y_train, y_test = clf.load_data(train_file)
clf.train(X_train, y_train)
clf.evaluate(X_test, y_test)
current_folder = os.getcwd()
model_file = os.path.join(current_folder, f"modelparameters2.pkl")
clf.save_model(model_file)
print(f" Model saved as a new file: {model_file}")
