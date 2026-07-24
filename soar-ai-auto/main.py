from fastapi import FastAPI
from pydantic import BaseModel
from ai.classifier import predict_attack
from ai.risk import get_attack_info
from ai.correlate import record_event, build_incident
from soar.blocker import (
    should_block,
    temp_block_ip,
    approve_permanent_block,
    reject_permanent_block,
    get_pending_approvals,
    list_blocked_ips,
    unblock_ip,
)
from soar.playbook import get_playbook
from soar.logger import log_action, get_logs

app = FastAPI()


class AlertLog(BaseModel):
    src_ip: str
    full_log: str
    rule_description: str


class IPRequest(BaseModel):
    src_ip: str


@app.post("/analyze")
def analyze_alert(alert: AlertLog):
    predicted_label = predict_attack(alert.rule_description)
    info = get_attack_info(predicted_label)

    record_event(alert.src_ip, predicted_label)
    incident = build_incident(alert.src_ip)
    risk = info["risk"]
    if incident["is_multi_stage"] and risk != "HIGH":
        risk = "HIGH"

    playbook = info["playbook"]
    recommendation = info["recommendation"]
    steps = get_playbook(playbook)

    if incident["is_multi_stage"]:
        print(f"\n[상관분석] Incident {incident['incident_id']} 감지")
        print(f"[상관분석] Attacker  : {alert.src_ip}")
        print(f"[상관분석] Attack Flow : {' -> '.join(incident['attack_flow'])}")
        print(f"[상관분석] Stage     : {incident['stage']}")
        print(f"[상관분석] Incident Risk Score : {incident['risk_score']}/100")

    print(f"[AI 예측] {predicted_label}")
    print(f"[위험도] {risk}")
    print(f"[권장조치] {recommendation}")

    if should_block(predicted_label):
        status = temp_block_ip(alert.src_ip, predicted_label)
        log_action(alert.src_ip, predicted_label, risk, playbook, status)
        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "risk": risk,
            "playbook": playbook,
            "steps": steps,
            "recommendation": recommendation,
            "action": status,
            "incident": incident,
        }
    else:
        log_action(alert.src_ip, predicted_label, risk, playbook, "none")
        return {
            "src_ip": alert.src_ip,
            "predicted_attack": predicted_label,
            "risk": risk,
            "playbook": playbook,
            "steps": steps,
            "recommendation": recommendation,
            "action": "none",
            "incident": incident,
        }


@app.get("/pending-approvals")
def pending_approvals():
    return get_pending_approvals()


@app.post("/approve")
def approve(request: IPRequest):
    return approve_permanent_block(request.src_ip)


@app.post("/reject")
def reject(request: IPRequest):
    return reject_permanent_block(request.src_ip)


@app.get("/blocked-ips")
def blocked_ips_list():
    return list_blocked_ips()


@app.post("/unblock")
def unblock(request: IPRequest):
    return unblock_ip(request.src_ip)


@app.get("/history")
def history():
    return {"history": get_logs()}
