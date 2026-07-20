from fastapi import FastAPI
from pydantic import BaseModel
from ai.classifier import predict_attack
from ai.risk import get_attack_info
from soar.blocker import should_block, temp_block_ip
from soar.playbook import get_playbook
from soar.logger import log_action, get_logs

app = FastAPI()


class AlertLog(BaseModel):
    src_ip: str
    full_log: str


@app.post("/analyze")
def analyze_alert(alert: AlertLog):
    predicted_label = predict_attack(alert.full_log)
    info = get_attack_info(predicted_label)

    risk = info["risk"]
    playbook = info["playbook"]
    recommendation = info["recommendation"]
    steps = get_playbook(playbook)

    print(f"[AI 예측] {predicted_label}")
    print(f"[위험도] {risk}")
    print(f"[권장조치] {recommendation}")

    if should_block(predicted_label):
        status = temp_block_ip(
            alert.src_ip,
            predicted_label
        )

        log_action(
            alert.src_ip,
            predicted_label,
            risk,
            playbook,
            status
        )

        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "risk": risk,
            "playbook": playbook,
            "steps": steps,
            "recommendation": recommendation,
            "action": status,
        }
    else:

        log_action(
            alert.src_ip,
            predicted_label,
            risk,
            playbook,
            "none"
         )

        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "risk": risk,
            "playbook": playbook,
            "steps": steps,
            "recommendation": recommendation,
            "action": "none",
        }

@app.get("/history")
def history():

    return {
        "history": get_logs()
    }
