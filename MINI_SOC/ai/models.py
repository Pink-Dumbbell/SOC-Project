"""
공통 데이터 모델
- Event    : Suricata/Wazuh 로그 한 줄을 정규화한 형태
- Incident : 같은 공격자(IP)의 이벤트들을 묶어서 만든 최종 결과물
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


@dataclass
class Event:
    timestamp: datetime
    src_ip: str
    dst_ip: Optional[str]
    source: str            # "suricata" | "wazuh"
    event_type: str        # "port_scan" | "web_access" | "sql_injection" | "webshell_upload" | "reverse_shell" | "other"
    signature: Optional[str]   # Suricata 룰 이름 or Wazuh rule description
    raw_log: str            # 원본 로그 한 줄 (감사/디버깅용)
    is_known: bool = True    # True: 시그니처로 확실히 탐지됨 / False: 패턴 추정
    confidence: float = 1.0  # is_known=False 일 때 신뢰도 (0.0~1.0)


@dataclass
class Incident:
    incident_id: str
    attacker_ip: str
    attack_type: str          # 대표 공격 유형 (가장 마지막/심각한 단계)
    attack_flow: List[str]    # ["port_scan", "web_access", "sql_injection", ...]
    events: List[Event]
    risk_score: int
    recommendation: List[str] = field(default_factory=list)
