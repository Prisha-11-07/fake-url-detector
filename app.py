from flask import Flask, render_template, request
from datetime import date
import json
import os

DATA_FILE = "scan_data.json"

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"date": str(date.today()), "count": 0,"threats": 0}
    
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

app = Flask(__name__)

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
    data = load_data()   # Always available

    if request.method == 'POST':
        url = request.form['url']

        # Reset if new day
        if data["date"] != str(date.today()):
            data["date"] = str(date.today())
            data["count"] = 0

        # Increment count
        data["count"] += 1
        save_data(data)

        try:
            # 🔴 Your ML function
            result, reasons, confidence = predict_url(url)

        except Exception as e:
            # ✅ Prevent crash (VERY IMPORTANT)
            result = "Error"
            confidence = 0
            reasons = [f"Error occurred: {str(e)}"]

        return render_template(
            'tool.html',
            result=result,
            confidence=confidence,
            reasons=reasons,
            scan_count=data["count"]
        )

    # GET request
    return render_template(
        'tool.html',
        scan_count=data["count"]
    )

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)