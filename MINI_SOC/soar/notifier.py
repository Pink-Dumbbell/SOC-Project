"""
SOAR - 관리자 알림 (Slack Webhook 기준, requests만 있으면 됨)
webhook_url이 없으면(None) 실제 전송 대신 콘솔에 출력만 한다 (dry-run).
"""

import requests
from ai.models import Incident


def build_message(incident: Incident) -> str:
    return (
        f"🚨 Incident {incident.incident_id}\n"
        f"Attacker: {incident.attacker_ip}\n"
        f"Attack Type: {incident.attack_type}\n"
        f"Attack Flow: {' -> '.join(incident.attack_flow)}\n"
        f"Risk Score: {incident.risk_score}/100\n"
        f"Recommendation: {', '.join(incident.recommendation) if incident.recommendation else '-'}"
    )


def send_slack_alert(webhook_url: str, incident: Incident) -> None:
    message = build_message(incident)

    if not webhook_url:
        print("[SOAR][DRY-RUN] Slack 알림 (실제 전송 안 함):")
        print(message)
        return

    try:
        res = requests.post(webhook_url, json={"text": message}, timeout=5)
        res.raise_for_status()
        print(f"[SOAR] Slack 알림 전송 완료 (Incident {incident.incident_id})")
    except requests.RequestException as e:
        print(f"[SOAR][ERROR] Slack 알림 전송 실패: {e}")
