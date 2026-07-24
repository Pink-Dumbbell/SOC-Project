"""
3단계: Risk Scoring
- 이벤트 종류별 가중치를 정의하고, 그룹(공격 시나리오) 안에서 가장 위험한 단계 기준으로 점수를 매긴다.
"""

from typing import List
from .models import Event

# 이벤트 타입별 위험도 가중치 (0~100)
RISK_WEIGHTS = {
    "port_scan": 10,
    "web_access": 5,
    "sql_injection": 70,
    "webshell_upload": 90,
    "reverse_shell": 100,
    "xss": 40,
    "other": 0,
}

# 발표/리포트용 표시 이름
DISPLAY_NAME = {
    "port_scan": "Nmap Scan",
    "web_access": "DVWA Access",
    "sql_injection": "SQL Injection",
    "webshell_upload": "WebShell Upload",
    "reverse_shell": "Reverse Shell",
    "xss": "XSS",
    "other": "Other",
}


def calculate_risk(events: List[Event]) -> int:
    """가장 위험한 단계의 점수를 최종 Risk Score로 사용.
    (필요하면 나중에 가중합 방식으로 바꿔도 됨: sum() 대신 max())"""
    if not events:
        return 0
    return max(RISK_WEIGHTS.get(e.event_type, 0) for e in events)


def build_attack_flow(events: List[Event]) -> List[str]:
    """시간순으로 정렬해서 사람이 읽기 좋은 공격 흐름 리스트 생성.

    연속으로 같은 event_type이 나오면(예: Suricata가 잡은 SQLi + Wazuh가 잡은 SQLi)
    하나로 합치되, 어떤 소스가 탐지했는지는 괄호로 남긴다.
    예: "SQL Injection (Suricata + Wazuh)"
    """
    events_sorted = sorted(events, key=lambda e: e.timestamp)

    flow: List[str] = []
    i = 0
    while i < len(events_sorted):
        current_type = events_sorted[i].event_type
        sources = [events_sorted[i].source]

        j = i + 1
        while j < len(events_sorted) and events_sorted[j].event_type == current_type:
            sources.append(events_sorted[j].source)
            j += 1

        display = DISPLAY_NAME.get(current_type, current_type)
        unique_sources = sorted(set(sources))
        if len(unique_sources) > 1 or len(sources) > 1:
            display += f" ({' + '.join(s.capitalize() for s in unique_sources)})"

        flow.append(display)
        i = j

    return flow
