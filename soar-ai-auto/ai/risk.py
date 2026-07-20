"""
AI가 예측한 공격 유형을 기반으로
위험도(Risk Level), Playbook, 권장 대응 방안을 제공한다.
"""

ATTACK_INFO = {
    "sql_injection": {
        "risk": "HIGH",
        "playbook": "SQL Injection Response",
        "recommendation": "공격 IP를 차단하고 웹 서버 및 DB 로그를 확인하세요."
    },

    "command_injection": {
        "risk": "HIGH",
        "playbook": "Command Injection Response",
        "recommendation": "공격 IP를 차단하고 서버 명령 실행 흔적을 조사하세요."
    },

    "file_upload": {
        "risk": "HIGH",
        "playbook": "Malicious File Upload Response",
        "recommendation": "업로드된 파일을 검사하고 웹쉘 여부를 확인하세요."
    },

    "directory_traversal": {
        "risk": "MEDIUM",
        "playbook": "Directory Traversal Investigation",
        "recommendation": "민감한 파일 접근 여부와 웹 서버 로그를 확인하세요."
    },

    "xss": {
        "risk": "MEDIUM",
        "playbook": "Cross-Site Scripting Investigation",
        "recommendation": "입력값 검증 및 출력 인코딩 정책을 점검하세요."
    },

    "ddos": {
        "risk": "MEDIUM",
        "playbook": "DDoS Response",
        "recommendation": "방화벽 및 네트워크 트래픽을 분석하세요."
    },

    "arp_spoofing": {
        "risk": "MEDIUM",
        "playbook": "ARP Spoofing Investigation",
        "recommendation": "ARP 테이블과 스위치 보안 설정을 확인하세요."
    },

    "file_inclusion": {
        "risk": "MEDIUM",
        "playbook": "File Inclusion Investigation",
        "recommendation": "웹 애플리케이션 파일 접근 정책을 점검하세요."
    },

    "brute_force": {
        "risk": "LOW",
        "playbook": "Brute Force Monitoring",
        "recommendation": "계정 잠금 정책과 로그인 실패 기록을 확인하세요."
    },

    "open_redirect": {
        "risk": "LOW",
        "playbook": "Open Redirect Investigation",
        "recommendation": "리다이렉트 대상 URL 검증 로직을 확인하세요."
    },

    "csrf": {
        "risk": "LOW",
        "playbook": "CSRF Investigation",
        "recommendation": "CSRF Token 적용 여부를 확인하세요."
    },

    "insecure_captcha": {
        "risk": "LOW",
        "playbook": "CAPTCHA Policy Review",
        "recommendation": "CAPTCHA 정책을 강화하세요."
    },

    "port_scanning": {
        "risk": "LOW",
        "playbook": "Port Scan Monitoring",
        "recommendation": "지속적인 포트 스캔 여부를 모니터링하세요."
    }
}


def get_attack_info(predicted_label: str) -> dict:
    """
    공격 유형에 따른 Risk, Playbook, 권장 대응을 반환한다.
    """

    return ATTACK_INFO.get(
        predicted_label,
        {
            "risk": "UNKNOWN",
            "playbook": "Unknown",
            "recommendation": "추가 분석이 필요합니다."
        }
    )
