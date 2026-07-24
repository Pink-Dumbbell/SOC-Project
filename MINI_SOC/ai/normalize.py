"""
1단계: Ingestion + Normalize
- Suricata eve.json  -> Event  (이미 시그니처로 판단된 Known Attack)
- Wazuh alerts.json  -> Event  (원본 로그 패턴을 직접 봐야 하는 Unknown Attack 후보)
"""

import json
import re
from datetime import datetime
from .models import Event

# ── Wazuh 원본 로그(raw_log)에서 공격 패턴을 잡아내는 정규식 ────────────────
# Suricata가 놓친(우회한) 공격도 여기서 잡아낸다.
SQLI_PATTERN = re.compile(r"(union\s*/?\*+/?\s*select|or\s+1=1|--\s|/\*.*\*/|select.+from)", re.IGNORECASE)
UPLOAD_PATTERN = re.compile(r"upload\.php", re.IGNORECASE)
SHELL_PATTERN = re.compile(r"nc\s+-e|/bin/(ba)?sh|bash\s+-i", re.IGNORECASE)


def _parse_timestamp(ts: str) -> datetime:
    """Suricata(offset 포함)와 Wazuh(offset 없음) 타임스탬프를 모두
    naive datetime으로 통일한다 (tzinfo 제거) -> 서로 비교/정렬 가능하게."""
    ts = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt


# ── Suricata ────────────────────────────────────────────────────────────
def _classify_suricata_signature(signature: str) -> str:
    sig = (signature or "").lower()
    if "nmap" in sig or "scan" in sig:
        return "port_scan"
    if "sql injection" in sig:
        return "sql_injection"
    if "xss" in sig:
        return "xss"
    return "other"


def load_suricata(path: str):
    """Suricata eve.json (JSON Lines)을 읽어 Event 리스트로 변환.
    Suricata가 alert를 냈다는 것 자체가 '시그니처로 확정된' Known Attack이므로 is_known=True."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            if data.get("event_type") != "alert":
                continue
            alert = data.get("alert", {})
            events.append(
                Event(
                    timestamp=_parse_timestamp(data["timestamp"]),
                    src_ip=data.get("src_ip"),
                    dst_ip=data.get("dest_ip"),
                    source="suricata",
                    event_type=_classify_suricata_signature(alert.get("signature")),
                    signature=alert.get("signature"),
                    raw_log=line,
                    is_known=True,
                    confidence=1.0,
                )
            )
    return events


# ── Wazuh ───────────────────────────────────────────────────────────────
def _classify_wazuh_log(full_log: str):
    """Wazuh가 그대로 넘겨준 원본 로그(full_log)를 직접 패턴 매칭해서 분류.
    Suricata 시그니처처럼 100% 확정이 아니므로 is_known=False, confidence로 신뢰도 표시."""
    if SHELL_PATTERN.search(full_log):
        return "reverse_shell", False, 0.90
    if UPLOAD_PATTERN.search(full_log):
        return "webshell_upload", False, 0.85
    if SQLI_PATTERN.search(full_log):
        return "sql_injection", False, 0.88
    if "login.php" in full_log.lower() or "/dvwa" in full_log.lower():
        return "web_access", True, 1.0
    return "other", False, 0.3


def load_wazuh(path: str):
    """Wazuh alerts.json (JSON Lines)을 읽어 Event 리스트로 변환."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            full_log = data.get("full_log", "")
            event_type, is_known, confidence = _classify_wazuh_log(full_log)
            events.append(
                Event(
                    timestamp=_parse_timestamp(data["timestamp"]),
                    src_ip=data.get("srcip"),
                    dst_ip=data.get("dstip"),
                    source="wazuh",
                    event_type=event_type,
                    signature=data.get("rule", {}).get("description"),
                    raw_log=full_log,
                    is_known=is_known,
                    confidence=confidence,
                )
            )
    return events
