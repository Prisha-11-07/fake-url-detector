from flask import Flask, render_template, request
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# Load dataset
data = pd.read_csv("urls.csv")

X = data['url']
y = data['label']

vectorizer = CountVectorizer()
X_vector = vectorizer.fit_transform(X)

model = LogisticRegression()
model.fit(X_vector, y)

# MAIN PAGE → opens login page
@app.route('/')
def home():
    return render_template('login.html')


# OTHER PAGES
@app.route('/movies')
def movies():
    return render_template('movies.html')

@app.route('/offers')
def offers():
    return render_template('offers.html')


if __name__ == '__main__':
    app.run(debug=True)