from flask import Flask, render_template, request, jsonify
from datetime import date
import json
import os
import requests
# 🔥 ML IMPORTS
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# 🔥 TRAINING DATA
train_urls = [
    "https://google.com",
    "https://amazon.com",
    "https://github.com",
    "https://bankofamerica.com",

    "http://login-bank.com",
    "http://secure-paypal-login.com",
    "http://verify-account-update.com",

    "http://paypal-secure-update-login.com",
    "http://amazon-login-security-alert.com",
    "http://bank-verification-alert.com",

    # short URLs
    "http://bit.ly/abc123",
    "http://tinyurl.com/fake",
]

train_labels = [
    "SAFE", "SAFE", "SAFE", "SAFE",
    "SUSPICIOUS", "SUSPICIOUS", "SUSPICIOUS",
    "FAKE", "FAKE", "FAKE",
    "SUSPICIOUS", "FAKE"
]

# 🔥 CREATE MODEL
vectorizer = TfidfVectorizer()
X_train = vectorizer.fit_transform(train_urls)

model = LogisticRegression()
model.fit(X_train, train_labels)

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co",
    "ow.ly", "is.gd", "buff.ly", "adf.ly"
]

DATA_FILE = "scan_data.json"

# ✅ Call external backend
BACKEND_URL = "https://fake-url-detector-ml.onrender.com/api/predict"


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"date": str(date.today()), "count": 0, "threats": 0}

    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


app = Flask(__name__)

import re

def normalize_url(url):
    url = url.strip()

    # Add protocol if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    return url


def extract_backend_value(data, keys):
    """Extract a value from backend response by trying multiple possible keys."""
    for key in keys:
        if key in data:
            return data[key]
    return None


# 🔥 IMPROVED DETECTION LOGIC
def predict_url(url):
    reasons = []
    score = 0

    url = normalize_url(url)
    url_lower = url.lower()

    # 🔴 HIGH RISK INDICATORS
    if "@" in url:
        reasons.append("Contains '@' (redirect attack)")
        score += 40

    if any(word in url_lower for word in ["login", "verify", "update", "secure", "account"]):
        reasons.append("Contains phishing keywords")
        score += 30

    if any(word in url_lower for word in ["bank", "paypal", "amazon"]):
        reasons.append("Impersonating trusted brand")
        score += 25

    # 🟠 MEDIUM RISK
    if url.startswith("http://"):
        reasons.append("Uses HTTP (not secure)")
        score += 20

    if "-" in url:
        reasons.append("Suspicious '-' in domain")
        score += 10

    if len(url) > 75:
        reasons.append("URL is too long")
        score += 15

    if url.count('.') > 3:
        reasons.append("Too many subdomains")
        score += 15

    # 🔗 SHORT URL DETECTION
    if any(short in url for short in SHORTENERS):
        reasons.append("Shortened URL detected")
        score += 25

    # 🤖 ML prediction (adds intelligence)
    features = vectorizer.transform([url])
    prediction = model.predict(features)[0]

    if prediction == "FAKE":
        score += 20
        reasons.append("ML model flags as phishing")
    elif prediction == "SUSPICIOUS":
        score += 10
        reasons.append("ML model flags as suspicious")

    # 🎯 FINAL DECISION
    if score >= 70:
        result = "Fake"
        risk = "High Risk"
    elif score >= 35:
        result = "Suspicious"
        risk = "Medium Risk"
    else:
        result = "Safe"
        risk = "Low Risk"

    confidence = min(score, 100)

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return result, reasons, confidence, risk

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/tool', methods=['GET', 'POST'])
def tool():
    data = load_data()
    result = None
    confidence = 0
    reasons = []
    risk = "Unknown"

    if request.method == 'POST':
        url = normalize_url(request.form.get('url', '').strip())

        # Update count
        if data["date"] != str(date.today()):
            data["date"] = str(date.today())
            data["count"] = 0

        data["count"] += 1
        save_data(data)

        backend_data = {}
        backend_available = False

        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=10
            )
            response.raise_for_status()
            backend_data = response.json()
            backend_available = True

            risk = backend_data.get("risk", risk)
            verdict = str(backend_data.get("verdict", "")).upper()

            if verdict == "FAKE":
                result = "Fake"
            elif verdict == "SUSPICIOUS":
                result = "Suspicious"
            elif verdict == "SAFE":
                result = "Safe"
            else:
                result = "Suspicious"

            confidence_value = extract_backend_value(
                backend_data,
                ["confidence", "score", "probability", "risk_score", "confidence_score"]
            )

            if confidence_value is not None:
                try:
                    val = float(confidence_value)
                    confidence = int(val * 100) if val <= 1 else int(val)
                except:
                    confidence = 0
            else:
                # If the backend doesn't provide confidence, derive from verdict
                confidence = 90 if result == "Fake" else 60 if result == "Suspicious" else 20

            message = backend_data.get("message") or backend_data.get("details") or backend_data.get("reasons")
            if isinstance(message, list):
                reasons = message
            elif isinstance(message, str) and message.strip():
                reasons = [message]
            elif isinstance(backend_data.get("reasons"), list):
                reasons = backend_data.get("reasons")
            else:
                reasons = ["No details provided"]

            if isinstance(backend_data.get('protocol'), str):
                reasons.append(f"Protocol: {backend_data.get('protocol')}")
            else:
                reasons.append(f"Protocol: {'HTTPS' if url.startswith('https://') else 'HTTP'}")

        except Exception as e:
            # Backend unavailable - fall back to local ML model
            print(f"Backend Error: {str(e)}")
            result, reasons, confidence, risk = predict_url(url)
            reasons.insert(0, "(Using local analysis - backend unavailable)")

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            risk=risk,
            scan_count=data["count"]
        )

    return render_template('tool.html', scan_count=data["count"], risk=risk)


# ✅ BACKEND API (same app)
@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json()
    url = data.get("url", "")

    result, reasons, confidence, risk = predict_url(url)

    if result == "Fake":
        verdict = "FAKE"
    elif result == "Suspicious":
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return jsonify({
        "verdict": verdict,
        "message": ", ".join(reasons),
        "protocol": "HTTPS" if "https" in url else "HTTP",
        "risk": risk
    })


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)