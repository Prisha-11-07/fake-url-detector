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

# ✅ Call local backend (same app)
BACKEND_URL = "http://127.0.0.1:5000/api/predict"


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

# 🔥 IMPROVED DETECTION LOGIC
def predict_url(url):
    reasons = []

    # 🔥 Normalize first
    url = normalize_url(url)

    # 🔥 Detect short URL
    if any(short in url for short in SHORTENERS):
        reasons.append("Uses URL shortening service (possible phishing)")
        short_flag = True
    else:
        short_flag = False

    # 🔥 ML Prediction
    features = vectorizer.transform([url])
    prediction = model.predict(features)[0]
    probs = model.predict_proba(features)[0]

    confidence = int(max(probs) * 100)

    # 🔥 Add reasoning
    if prediction == "SAFE":
        reasons.append("No phishing patterns detected")
    elif prediction == "SUSPICIOUS":
        reasons.append("Contains suspicious structure or keywords")
    else:
        reasons.append("Matches phishing patterns")

    # 🔥 Boost risk if short URL
    if short_flag and prediction == "SAFE":
        prediction = "SUSPICIOUS"
        reasons.append("Short URL increases risk level")

    # 🔥 Final mapping
    if prediction == "SAFE":
        result = "Safe"
    elif prediction == "SUSPICIOUS":
        result = "Suspicious"
    else:
        result = "Fake"

    reasons.append(f"Model confidence: {confidence}%")

    return result, reasons, confidence

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/tool', methods=['GET', 'POST'])
def tool():
    data = load_data()

    if request.method == 'POST':
        url = normalize_url(request.form['url'])

        # Update count
        if data["date"] != str(date.today()):
            data["date"] = str(date.today())
            data["count"] = 0

        data["count"] += 1
        save_data(data)

        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=10
            )

            backend_data = response.json()

            verdict = backend_data.get("verdict", "").upper()

            if verdict == "FAKE":
                result = "Fake"
                confidence = 100
            elif verdict == "SUSPICIOUS":
                result = "Suspicious"
                confidence = 60
            else:
                result = "Safe"
                confidence = 0

            reasons = [
                backend_data.get("message", "No details provided"),
                f"Protocol: {backend_data.get('protocol', 'Unknown')}"
            ]

        except Exception as e:
            result = "Error"
            confidence = 0
            reasons = [f"Backend Error: {str(e)}"]

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            scan_count=data["count"]
        )

    return render_template('tool.html', scan_count=data["count"])


# ✅ BACKEND API (same app)
@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json()
    url = data.get("url", "")

    result, reasons, confidence = predict_url(url)

    if result == "Fake":
        verdict = "FAKE"
    elif result == "Suspicious":
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return jsonify({
        "verdict": verdict,
        "message": ", ".join(reasons),
        "protocol": "HTTPS" if "https" in url else "HTTP"
    })


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)