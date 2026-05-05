import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

data = pd.read_csv("urls.csv")

X = data['url']
y = data['label']

vectorizer = CountVectorizer()
X_vector = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_vector, y, test_size=0.2)

model = LogisticRegression()
model.fit(X_train, y_train)

print("Model trained successfully!")

test_url = ["http://secure-login.example.com"]
test_vector = vectorizer.transform(test_url)

prediction = model.predict(test_vector)
print("Prediction:", prediction)