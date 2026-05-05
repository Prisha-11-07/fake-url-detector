from flask import Flask, render_template, request
from datetime import date
import json
import os
import requests

DATA_FILE = "scan_data.json"

BACKEND_URL = "https://cameo-unmasked-gracious.ngrok-free.dev/api/predict"


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"date": str(date.today()), "count": 0, "threats": 0}
    
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


app = Flask(__name__)


# 🔹 Local fallback scanner
def predict_url(url):
    reasons = []
    score = 0

    if "https" not in url:
        reasons.append("No HTTPS encryption")
        score += 25

    if "login" in url.lower():
        reasons.append("Contains 'login' (phishing keyword)")
        score += 15

    if "bank" in url.lower():
        reasons.append("Contains 'bank' keyword")
        score += 15

    if "@" in url:
        reasons.append("Contains '@' redirect symbol")
        score += 15

    if "-" in url:
        reasons.append("Contains '-' which may indicate fake domain")
        score += 10

    if len(url) > 75:
        reasons.append("URL length is suspiciously long")
        score += 20

    result = "Fake" if score > 50 else "Safe"
    confidence = min(score, 100)

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return result, reasons, confidence


def fallback_scan(url, error_message=None):
    result, reasons, confidence = predict_url(url)

    if error_message:
        reasons.insert(0, f"Backend unavailable: {error_message}")
    else:
        reasons.insert(0, "Backend fallback activated. Using local scan.")

    return result, reasons, confidence


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

        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=10
            )
            response.raise_for_status()
            backend_data = response.json()

            print("✅ Backend Response:", backend_data)

            # 🔹 Get verdict
            verdict = None
            for key in ["verdict", "prediction", "result", "label", "status"]:
                if key in backend_data:
                    verdict = str(backend_data[key]).strip()
                    break

            if verdict:
                v = verdict.upper()

                if v in ["FAKE", "PHISHING", "MALICIOUS", "UNSAFE"]:
                    result = "Fake"
                elif v in ["SUSPICIOUS", "UNKNOWN", "WARN"]:
                    result = "Suspicious"
                elif v in ["SAFE", "LEGITIMATE", "CLEAN", "GOOD"]:
                    result = "Safe"
                else:
                    result = "Suspicious"
            else:
                result = "Suspicious"

            # 🔹 Confidence
            confidence_value = None
            for key in ["confidence", "score", "probability"]:
                if key in backend_data:
                    confidence_value = backend_data[key]
                    break

            if confidence_value is not None:
                try:
                    val = float(confidence_value)
                    confidence = int(val * 100) if val <= 1 else int(val)
                except:
                    confidence = 0

            # 🔹 Default confidence fix
            if confidence == 0:
                if result == "Fake":
                    confidence = 90
                elif result == "Suspicious":
                    confidence = 60
                elif result == "Safe":
                    confidence = 20

            # 🔹 Reasons
            if isinstance(backend_data, dict):
                reasons.append("--- Backend Analysis Results ---")
                for k, v in backend_data.items():
                    reasons.append(f"{k.upper()}: {v}")

        except Exception as e:
            # 🔥 IMPORTANT FIX → always fallback instead of breaking UI
            result, reasons, confidence = fallback_scan(url, str(e))

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            scan_count=data["count"]
        )

    return render_template('tool.html', scan_count=data["count"])


if __name__ == '__main__':
    app.run(debug=True)