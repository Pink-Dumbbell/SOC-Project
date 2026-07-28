from fastapi import FastAPI
from pydantic import BaseModel
from ai.classifier import predict_attack
from ai.risk import calculate_risk
from ai.correlate import record_event, build_incident
from soar.blocker import (
    handle_risk,
    approve_permanent_block,
    reject_permanent_block,
    get_pending_approvals,
    list_blocked_ips,
    unblock_ip,
    list_medium_alerts,
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
    predicted_label = predict_attack(alert.rule_description, alert.full_log)

    record_event(alert.src_ip, predicted_label)
    incident = build_incident(alert.src_ip)
    event_count = incident.get("event_count", 1)
    label_flow = incident.get("labels", [predicted_label])

    risk_result = calculate_risk(
        predicted_label,
        event_count=event_count,
        attack_flow=label_flow,
        full_log=alert.full_log,
    )
    risk = risk_result["risk"]
    score = risk_result["score"]
    playbook = risk_result["playbook"]
    recommendation = risk_result["recommendation"]
    steps = get_playbook(playbook)

    if incident.get("is_multi_stage"):
        print(f"\n[상관분석] Incident {incident['incident_id']} 감지")
        print(f"[상관분석] Attacker  : {alert.src_ip}")
        print(f"[상관분석] Attack Flow : {' -> '.join(incident['attack_flow'])}")
        print(f"[상관분석] Stage     : {incident['stage']}")

    print(f"[AI 예측] {predicted_label}")
    print(f"[Risk Score] {score} ({risk})")
    print(f"[권장조치] {recommendation}")

    status = handle_risk(alert.src_ip, predicted_label, risk, score)
    log_action(alert.src_ip, predicted_label, risk, playbook, status)

    return {
        "src_ip": alert.src_ip,
        "predicted_attack": predicted_label,
        "risk": risk,
        "score": score,
        "playbook": playbook,
        "steps": steps,
        "recommendation": recommendation,
        "action": status,
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


@app.get("/medium-alerts")
def medium_alerts_list():
    return list_medium_alerts()


@app.get("/history")
def history():
    return {"history": get_logs()}
