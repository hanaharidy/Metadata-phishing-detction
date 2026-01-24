import pandas as pd
from defense_model1 import PhishingDefenseSystem  
import os

file_path = r"C:\Users\DELL\Downloads\denv\denv\dataset\train_data.xlsx"  
df = pd.read_excel(file_path)


system = PhishingDefenseSystem()
df = system.preprocess(df)

X_train = system.fit_transform(df)
y_train = df["label"]
system.model.fit(X_train, y_train)
print(" Model trained successfully")
system.save_model() 

