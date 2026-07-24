"""
2단계: Correlation (상관분석)
- 같은 src_ip의 이벤트를 시간 윈도우 안에서 하나의 그룹(공격 시나리오)으로 묶는다.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict
from .models import Event


def group_by_ip(events: List[Event], window_minutes: int = 10) -> Dict[str, List[Event]]:
    """
    src_ip 별로 묶되, 같은 IP라도 마지막 이벤트로부터 window_minutes를 초과해서
    떨어진 이벤트는 별도 그룹으로 분리한다 (너무 옛날 이벤트가 섞이지 않게).
    """
    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for e in sorted(events, key=lambda x: x.timestamp):
        by_ip[e.src_ip].append(e)

    result: Dict[str, List[Event]] = {}
    for ip, ip_events in by_ip.items():
        groups: List[List[Event]] = []
        current_group: List[Event] = []

        for e in ip_events:
            if current_group and (e.timestamp - current_group[-1].timestamp) > timedelta(minutes=window_minutes):
                groups.append(current_group)
                current_group = []
            current_group.append(e)
        if current_group:
            groups.append(current_group)

        # 같은 IP에서 시간 윈도우가 여러 번 끊기면 incident도 여러 개가 되어야 하므로
        # 그룹마다 key를 ip / ip#2 / ip#3 ... 로 구분
        for idx, g in enumerate(groups, start=1):
            key = ip if idx == 1 else f"{ip}#{idx}"
            result[key] = g

    return result
