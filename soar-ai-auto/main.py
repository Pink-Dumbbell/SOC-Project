from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from response import should_block, temp_block_ip

app = FastAPI()

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


class AlertLog(BaseModel):
    src_ip: str
    full_log: str


@app.post("/analyze")
def analyze_alert(alert: AlertLog):
    X = vectorizer.transform([alert.full_log])
    predicted_label = model.predict(X)[0]
    print(f"[AI 예측] {predicted_label}")

    if should_block(predicted_label):
        status = temp_block_ip(
            alert.src_ip,
            predicted_label
        )

        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "action": status,
        }
    else:
        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "action": "none",
        }
