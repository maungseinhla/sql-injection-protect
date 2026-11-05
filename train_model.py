import pandas as pd
import numpy as np
import urllib.parse
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


dataset_path = "Modified_SQL_Dataset.csv"
df = pd.read_csv(dataset_path)


df = df.dropna()

# ၂။ Preprocessing Function 
def clean_payload(text):
    text = str(text)
    
    text = urllib.parse.unquote(text)
    
    text = text.lower().strip()
    return text

print("Data are being Preprocessing... ")
df['clean_query'] = df['Query'].apply(clean_payload)

X = df['clean_query']
y = df['Label'].astype(int)


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)


print("TF-IDF Vectorization is started ...")
vectorizer = TfidfVectorizer(
    analyzer='char',
    ngram_range=(2, 6),  
    max_features=50000   
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)


print("Model is started  Training...")
model = LogisticRegression(max_iter=1000, C=5.0)
model.fit(X_train_vec, y_train)


y_pred = model.predict(X_test_vec)

print("\n--- Model Evaluation Results ---")
print(f"Accuracy Score: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Benign (0)", "SQLi (1)"]))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))


print("\nsaving the trained model and vectorizer...")
joblib.dump(vectorizer, 'vectorizer.pkl')
joblib.dump(model, 'sqli_model.pkl')
print("saved 'vectorizer.pkl' and  'sqli_model.pkl'")