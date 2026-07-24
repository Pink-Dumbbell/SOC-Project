"""
Wazuh가 이미 판단한 rule.description을 보고
우리 표준 라벨(sql_injection, xss 등)로 정리하는 역할.
ML 없음 — 키워드 매칭만 함.
"""

LABEL_KEYWORDS = {
    "sql injection": "sql_injection",
    "xss": "xss",
    "cross site": "xss",
    "directory traversal": "directory_traversal",
    "path traversal": "directory_traversal",
    "command injection": "command_injection",
    "file upload": "file_upload",
    "brute force": "brute_force",
    "failed login": "brute_force",
    "port scan": "port_scanning",
}


def predict_attack(rule_description: str) -> str:
    """
    Wazuh의 rule.description 문장을 보고 표준 라벨로 변환한다.
    매칭되는 키워드가 없으면 "unknown" 반환.
    """
    if not rule_description:
        return "unknown"

    description_lower = rule_description.lower()

    for keyword, label in LABEL_KEYWORDS.items():
        if keyword in description_lower:
            return label

    return "unknown"
