"""
Mini SOC - AI + SOAR 실행 진입점

실행:
    python main.py

흐름:
    [AI] 로그 읽기 -> 정규화 -> (분류는 normalize 단계에 포함) -> 상관분석 -> 위험도 계산
    [SOAR] 위험도가 임계치 이상이면 -> IP 차단 + 알림
"""

import os
import uuid

from ai.normalize import load_suricata, load_wazuh
from ai.correlate import group_by_ip
from ai.risk import calculate_risk, build_attack_flow
from ai.models import Incident

from soar.blocker import block_ip
from soar.notifier import send_slack_alert

# ── 설정 (환경변수로 주입, 없으면 기본값 사용) ──────────────────────────
# Docker 실행 시 -e 옵션이나 docker-compose.yml의 environment로 값을 바꿀 수 있음
SURICATA_LOG_PATH = os.getenv("SURICATA_LOG_PATH", "sample_logs/suricata_eve.json")
WAZUH_LOG_PATH = os.getenv("WAZUH_LOG_PATH", "sample_logs/wazuh_alerts.json")

RISK_BLOCK_THRESHOLD = int(os.getenv("RISK_BLOCK_THRESHOLD", "90"))
CORRELATION_WINDOW_MIN = int(os.getenv("CORRELATION_WINDOW_MIN", "10"))

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")          # 없으면 None -> dry-run
DRY_RUN_BLOCK = os.getenv("DRY_RUN_BLOCK", "true").lower() != "false"


def main():
    # 1. Ingestion + Normalize
    events = []
    events += load_suricata(SURICATA_LOG_PATH)
    events += load_wazuh(WAZUH_LOG_PATH)
    print(f"[AI] 총 {len(events)}개 이벤트 로드 완료 (Suricata + Wazuh)\n")

    # 2. Correlation (같은 IP + 시간창으로 묶기)
    groups = group_by_ip(events, window_minutes=CORRELATION_WINDOW_MIN)

    # 3. Risk Scoring + Incident 생성 + SOAR 실행
    for ip_key, group_events in groups.items():
        attack_flow = build_attack_flow(group_events)
        risk_score = calculate_risk(group_events)
        attacker_ip = group_events[0].src_ip

        incident = Incident(
            incident_id=f"#{uuid.uuid4().hex[:6]}",
            attacker_ip=attacker_ip,
            attack_type=attack_flow[-1] if attack_flow else "Unknown",
            attack_flow=attack_flow,
            events=group_events,
            risk_score=risk_score,
        )

        if incident.risk_score >= RISK_BLOCK_THRESHOLD:
            incident.recommendation = ["SOAR 실행", "공격 IP 차단", "관리자 알림"]
            block_ip(incident.attacker_ip, dry_run=DRY_RUN_BLOCK)
        else:
            incident.recommendation = ["모니터링 유지"]

        send_slack_alert(SLACK_WEBHOOK_URL, incident)

        # 콘솔 리포트 출력
        print("=" * 50)
        print(f"Incident ID   : {incident.incident_id}")
        print(f"Attacker      : {incident.attacker_ip}")
        print(f"Attack Type   : {incident.attack_type}")
        print(f"Attack Flow   : {' -> '.join(incident.attack_flow)}")
        print(f"Risk Score    : {incident.risk_score}/100")
        print(f"Recommendation: {', '.join(incident.recommendation)}")
        print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
