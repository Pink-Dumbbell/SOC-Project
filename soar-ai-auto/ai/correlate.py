"""
같은 공격자(IP)가 벌인 여러 alert를 시간 윈도우 안에서 묶어
하나의 공격 시나리오(Incident)로 재구성하는 상관분석 모듈.

설계 원칙:
- 같은 IP + 시간 정보로 상관분석(Incident 생성)
- Recon -> Exploitation -> Post-Exploitation 단계로 공격 흐름 판단
"""

import threading
import uuid
from datetime import datetime, timedelta

CORRELATION_WINDOW_MINUTES = 10

# 공격 유형별 Kill Chain 단계
STAGE_MAP = {
    "port_scanning": "Reconnaissance",
    "brute_force": "Exploitation",
    "xss": "Exploitation",
    "csrf": "Exploitation",
    "open_redirect": "Exploitation",
    "insecure_captcha": "Exploitation",
    "directory_traversal": "Exploitation",
    "file_inclusion": "Exploitation",
    "ddos": "Exploitation",
    "arp_spoofing": "Exploitation",
    "sql_injection": "Exploitation",
    "command_injection": "Post-Exploitation",
    "file_upload": "Post-Exploitation",
}
STAGE_ORDER = ["Reconnaissance", "Exploitation", "Post-Exploitation"]

# 공격 유형별 위험도 점수 (0~100) — Incident 전체 위험도 계산용
RISK_SCORE_BY_LABEL = {
    "port_scanning": 10,
    "brute_force": 20,
    "csrf": 20,
    "open_redirect": 20,
    "insecure_captcha": 15,
    "xss": 40,
    "directory_traversal": 50,
    "file_inclusion": 50,
    "ddos": 45,
    "arp_spoofing": 45,
    "sql_injection": 70,
    "file_upload": 90,
    "command_injection": 95,
}

DISPLAY_NAME = {
    "port_scanning": "Port Scan",
    "brute_force": "Brute Force",
    "xss": "XSS",
    "csrf": "CSRF",
    "open_redirect": "Open Redirect",
    "insecure_captcha": "Insecure CAPTCHA",
    "directory_traversal": "Directory Traversal",
    "file_inclusion": "File Inclusion",
    "ddos": "DDoS",
    "arp_spoofing": "ARP Spoofing",
    "sql_injection": "SQL Injection",
    "file_upload": "File Upload",
    "command_injection": "Command Injection",
    "unknown": "Unknown",
}

# src_ip -> [{"timestamp": datetime, "label": str}, ...]
ip_event_history = {}
lock = threading.Lock()


def record_event(src_ip: str, predicted_label: str) -> None:
    """이번 alert를 기록하고, 시간 윈도우 밖으로 벗어난 옛날 기록은 정리한다."""
    now = datetime.now()

    with lock:
        history = ip_event_history.setdefault(src_ip, [])
        history.append({"timestamp": now, "label": predicted_label})

        cutoff = now - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
        ip_event_history[src_ip] = [e for e in history if e["timestamp"] >= cutoff]


def _get_history(src_ip: str):
    with lock:
        return sorted(ip_event_history.get(src_ip, []), key=lambda e: e["timestamp"])


def build_incident(src_ip: str) -> dict:
    """
    최근 시간 윈도우 안에서 이 IP가 벌인 이벤트들을 모아
    하나의 Incident(공격 시나리오)로 재구성한다.
    """
    history = _get_history(src_ip)

    labels = [e["label"] for e in history]
    attack_flow = [DISPLAY_NAME.get(label, label) for label in labels]

    stages_reached = {STAGE_MAP.get(label) for label in labels}
    stages_reached.discard(None)

    # 서로 다른 Kill Chain 단계를 2개 이상 거쳤으면 연속 공격 시나리오로 판단
    is_multi_stage = len(stages_reached) >= 2

    # 지금까지 도달한 가장 마지막(심각한) 단계
    current_stage = None
    for stage in reversed(STAGE_ORDER):
        if stage in stages_reached:
            current_stage = stage
            break

    # Incident 위험도 = 이 시나리오 안에서 가장 위험한 단계의 점수
    risk_score = max((RISK_SCORE_BY_LABEL.get(label, 0) for label in labels), default=0)

    return {
        "incident_id": f"INC-{uuid.uuid4().hex[:8]}",
        "attacker_ip": src_ip,
        "attack_flow": attack_flow,
        "stage": current_stage,
        "is_multi_stage": is_multi_stage,
        "risk_score": risk_score,
        "event_count": len(history),
    }