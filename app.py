from flask import Flask, render_template, request

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
    result = None
    reasons = []
    confidence = 0

    if request.method == 'POST':
        url = request.form.get('url', '')
        result, reasons, confidence = predict_url(url)

    return render_template('tool.html',
                           result=result,
                           reasons=reasons,
                           confidence=confidence)


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)