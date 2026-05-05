from flask import Flask, render_template, request
from datetime import date
import json
import os
import requests

app = Flask(__name__)

DATA_FILE = "scan_data.json"

# ✅ Your deployed backend API
BACKEND_URL = "https://url-detection-b73v.onrender.com/api/predict"


# -------------------------------
# Load & Save Scan Data
# -------------------------------
def load_data():
    if not os.path.exists(DATA_FILE):
        return {"date": str(date.today()), "count": 0}
    
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


# -------------------------------
# Local fallback scanner
# -------------------------------
def predict_url(url):
    reasons = []
    score = 0

    if not url.startswith("https"):
        reasons.append("No HTTPS encryption")
        score += 25

    if "login" in url.lower():
        reasons.append("Contains 'login' keyword")
        score += 15

    if "bank" in url.lower():
        reasons.append("Contains 'bank' keyword")
        score += 15

    if "@" in url:
        reasons.append("Contains '@' redirect")
        score += 15

    if "-" in url:
        reasons.append("Contains '-' in domain")
        score += 10

    if len(url) > 75:
        reasons.append("URL too long")
        score += 20

    result = "Fake" if score > 50 else "Safe"
    confidence = min(score, 100)

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return result, reasons, confidence


def fallback_scan(url):
    result, reasons, confidence = predict_url(url)
    reasons.insert(0, "⚠ Backend unavailable - Local scan used")
    return result, reasons, confidence


# -------------------------------
# Extract values safely
# -------------------------------
def extract_value(data, keys):
    if not isinstance(data, dict):
        return None

    for key in keys:
        if key in data:
            return data[key]

    for value in data.values():
        if isinstance(value, dict):
            nested = extract_value(value, keys)
            if nested is not None:
                return nested

    return None


# -------------------------------
# Routes
# -------------------------------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/tool', methods=['GET', 'POST'])
def tool():
    data = load_data()

    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            return render_template('tool.html', scan_count=data["count"])

        # Reset daily count
        if data["date"] != str(date.today()):
            data["date"] = str(date.today())
            data["count"] = 0

        data["count"] += 1
        save_data(data)

        result = "Suspicious"
        confidence = 50
        reasons = []
        used_fallback = False
        backend_error = None

        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=20
            )

            response.raise_for_status()
            backend_data = response.json()

            print("Backend response:", backend_data)

            # -------------------------------
            # Verdict Mapping
            # -------------------------------
            verdict = extract_value(
                backend_data,
                ["verdict", "prediction", "result", "label"]
            )

            if verdict:
                v = str(verdict).lower()

                if v in ["fake", "phishing", "malicious", "1", "true"]:
                    result = "Fake"
                elif v in ["safe", "legitimate", "0", "false"]:
                    result = "Safe"
                else:
                    result = "Suspicious"

            # -------------------------------
            # Confidence
            # -------------------------------
            conf_val = extract_value(
                backend_data,
                ["confidence", "probability", "score"]
            )

            if conf_val is not None:
                val = float(conf_val)
                confidence = int(val * 100) if val <= 1 else int(val)

            # Default confidence if missing
            if confidence == 0:
                confidence = 90 if result == "Fake" else 30

            # -------------------------------
            # Reasons
            # -------------------------------
            if "reasons" in backend_data:
                reasons = backend_data["reasons"]

        except Exception as e:
            print("Backend error:", e)
            used_fallback = True
            backend_error = str(e)
            result, reasons, confidence = fallback_scan(url)

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            scan_count=data["count"],
            used_fallback=used_fallback,
            backend_error=backend_error
        )

    return render_template('tool.html', scan_count=data["count"])


# -------------------------------
# Run App
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)