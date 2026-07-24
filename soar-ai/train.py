import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# 1. CSV 불러오기
df = pd.read_csv("dataset.csv")

# 2. 문자열(full_log)을 숫자 벡터로 변환
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["full_log"])

# 3. 정답(label)
y = df["label"]

# 4. 모델 학습
model = LogisticRegression()
model.fit(X, y)

# 5. 모델과 벡터라이저를 파일로 저장
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("학습 완료! model.pkl, vectorizer.pkl 생성됨")