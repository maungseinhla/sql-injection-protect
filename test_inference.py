import joblib
import urllib.parse


vectorizer = joblib.load('vectorizer.pkl')
model = joblib.load('sqli_model.pkl')

test_inputs = [
    "SELECT * FROM users WHERE username = 'admin' OR 1=1--",
    "John Doe",
    "1' UNION SELECT null, username, password FROM users--",
    "How to install python on windows?",
    "admin'--",
    "search_query=laptop&category=electronics"
]

print("--- Test Predictions ---")
for text in test_inputs:
    cleaned = urllib.parse.unquote(text).lower().strip()
    vec = vectorizer.transform([cleaned])
    
    
    prob = model.predict_proba(vec)[0][1]
    is_sqli = prob >= 0.7  
    
    result = "🚨 BLOCKED (SQLi)" if is_sqli else "✅ ALLOWED (Clean)"
    print(f"Input: {text}")
    print(f"Confidence: {prob * 100:.2f}% -> {result}\n")