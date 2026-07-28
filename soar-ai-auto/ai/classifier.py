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
    "arp spoofing": "arp_spoofing",
    "session hijack": "session_hijacking",
}

# rule.description이 범용 문구("Common web attack" 등)일 때,
# 요청 URL 패턴으로 실제 공격 유형을 보강 판단하기 위한 키워드
URL_PATTERN_KEYWORDS = {
    "../": "directory_traversal",
    "..%2f": "directory_traversal",
    "/etc/passwd": "directory_traversal",
    "union select": "sql_injection",
    "<script": "xss",
    ";cat ": "command_injection",
    "|whoami": "command_injection",
}


def predict_attack(rule_description: str, url: str = "") -> str:
    """
    Wazuh의 rule.description 문장을 우선으로 보고,
    매칭이 안 되면 요청 URL 패턴으로 보강 판단한다.
    """
    if rule_description:
        description_lower = rule_description.lower()
        for keyword, label in LABEL_KEYWORDS.items():
            if keyword in description_lower:
                return label

    if url:
        url_lower = url.lower()
        for pattern, label in URL_PATTERN_KEYWORDS.items():
            if pattern in url_lower:
                return label

    return "unknown"
