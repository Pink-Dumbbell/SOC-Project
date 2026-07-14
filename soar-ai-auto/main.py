from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from response import generate_block_command, should_block, execute_block_on_gateway

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

    if should_block(predicted_label):
        command = generate_block_command(alert.src_ip)
        result = execute_block_on_gateway(command)   # ← 실제 실행 추가!

        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "action": "block",
            "command": command,
            "execution_result": result,
        }
    else:
        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "action": "none",
        }