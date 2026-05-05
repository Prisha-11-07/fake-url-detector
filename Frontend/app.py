from flask import Flask, render_template, request
from datetime import date
import json
import os
import requests

DATA_FILE = "scan_data.json"

# ✅ Call external backend
BACKEND_URL = "https://fake-url-detector-ml.onrender.com/predict"


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"date": str(date.today()), "count": 0, "threats": 0}

    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


app = Flask(__name__)

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

        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=10
            )
            response.raise_for_status()
            backend_data = response.json()

            prediction = str(backend_data.get("prediction", backend_data.get("verdict", ""))).strip()
            prediction_lower = prediction.lower()

            if prediction_lower in ["fake", "malicious", "phishing", "malware"]:
                result = "Fake"
                risk = "High Risk"
            elif prediction_lower in ["suspicious", "unknown", "uncertain"]:
                result = "Suspicious"
                risk = "Medium Risk"
            elif prediction_lower in ["safe", "legitimate", "benign"]:
                result = "Safe"
                risk = "Low Risk"
            else:
                result = "Suspicious"
                risk = "Medium Risk"

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
                confidence = 0

            reasons = backend_data.get("reasons") or backend_data.get("details") or backend_data.get("message")
            if isinstance(reasons, str):
                reasons = [reasons]
            if not isinstance(reasons, list):
                reasons = ["No details provided by backend"]

        except Exception as e:
            result = "Error"
            confidence = 0
            reasons = [f"Backend Error: {str(e)}"]

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            risk=risk,
            scan_count=data["count"]
        )

    return render_template('tool.html', scan_count=data["count"], risk=risk)


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)