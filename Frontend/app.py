from flask import Flask, render_template, request
from datetime import date
import json
import os
import requests   # ✅ ADDED

DATA_FILE = "scan_data.json"

# ✅ BACKEND API LINK (ADDED)
BACKEND_URL = "https://cameo-unmasked-gracious.ngrok-free.dev/api/predict"


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"date": str(date.today()), "count": 0,"threats": 0}
    
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

app = Flask(__name__)

# 🔴 (Your old ML function kept as backup — no change)
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

        if data["date"] != str(date.today()):
            data["date"] = str(date.today())
            data["count"] = 0

        data["count"] += 1
        save_data(data)

        result = "Unknown"
        confidence = 0
        reasons = []

        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=10
            )
            response.raise_for_status()
            backend_data = response.json()

            # Try to find the main verdict from common backend keys
            verdict = None
            for key in ["verdict", "prediction", "result", "label", "status"]:
                if key in backend_data:
                    verdict = str(backend_data[key]).strip()
                    break

            if verdict:
                verdict_upper = verdict.upper()
                if verdict_upper in ["FAKE", "PHISHING", "MALICIOUS", "UNSAFE"]:
                    result = "Fake"
                elif verdict_upper in ["SUSPICIOUS", "UNKNOWN", "WARN"]:
                    result = "Suspicious"
                elif verdict_upper in ["SAFE", "LEGITIMATE", "CLEAN", "GOOD"]:
                    result = "Safe"
                else:
                    result = verdict.title()

            # Parse confidence from common backend keys
            confidence_value = None
            for key in ["confidence", "score", "probability", "certainty"]:
                if key in backend_data:
                    confidence_value = backend_data[key]
                    break

            if confidence_value is not None:
                try:
                    confidence_float = float(confidence_value)
                    confidence = int(confidence_float * 100) if confidence_float <= 1 else int(confidence_float)
                except Exception:
                    confidence = 0

            if confidence == 0:
                if result == "Fake":
                    confidence = 90
                elif result == "Suspicious":
                    confidence = 60
                elif result == "Safe":
                    confidence = 10
                else:
                    confidence = 50

            # Build user-friendly reasons
            if isinstance(backend_data, dict):
                if backend_data.get("message"):
                    reasons.append(str(backend_data.get("message")))
                if backend_data.get("reason"):
                    reasons.append(str(backend_data.get("reason")))
                if backend_data.get("details"):
                    details = backend_data.get("details")
                    if isinstance(details, list):
                        reasons.extend([str(item) for item in details])
                    else:
                        reasons.append(str(details))
                if backend_data.get("protocol"):
                    reasons.append(f"Protocol: {backend_data.get('protocol')}")
                if backend_data.get("domain"):
                    reasons.append(f"Domain: {backend_data.get('domain')}")

            if not reasons:
                reasons = ["No additional details were returned by the backend."]

        except requests.exceptions.RequestException as e:
            result = "Error"
            confidence = 0
            reasons = [f"Backend request failed: {str(e)}"]
        except ValueError:
            result = "Error"
            confidence = 0
            reasons = ["Could not parse the backend response."]

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            scan_count=data["count"]
        )

    return render_template(
        'tool.html',
        scan_count=data["count"]
    )



if __name__ == '__main__':
    app.run(debug=True)