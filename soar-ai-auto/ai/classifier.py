import joblib

# 모델은 프로그램 시작 시 한 번만 로드
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


def predict_attack(full_log: str) -> str:
    """
    Alert 로그를 받아 공격 유형을 예측한다.
    """
    X = vectorizer.transform([full_log])
    predicted_label = model.predict(X)[0]
    return predicted_label
