from flask import Flask, render_template, request
from datetime import date
import json
import os
import requests

DATA_FILE = "scan_data.json"

# 🔗 BACKEND API (make sure this is ACTIVE)
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


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/tool', methods=['GET', 'POST'])
def tool():
    data = load_data()

    if request.method == 'POST':
        url = request.form['url']

        # Update daily scan count
        if data["date"] != str(date.today()):
            data["date"] = str(date.today())
            data["count"] = 0

        data["count"] += 1
        save_data(data)

        try:
            # 🔥 Call backend API
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=20
            )

            print("Status Code:", response.status_code)
            print("Raw Response:", response.text)

            # ❌ If backend not working → STOP
            if response.status_code != 200:
                raise Exception("Backend not responding properly")

            # ❌ If response not JSON → STOP
            try:
                backend_data = response.json()
            except:
                raise Exception("Backend did not return valid JSON")

            # ❌ Validate backend output
            verdict = backend_data.get("verdict", "").upper()
            if verdict not in ["FAKE", "SAFE", "SUSPICIOUS"]:
                raise Exception("Invalid backend output format")

            # ✅ USE ONLY BACKEND RESULT
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
            # ❌ DO NOT FAKE RESULT
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

    return render_template(
        'tool.html',
        scan_count=data["count"]
    )


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)