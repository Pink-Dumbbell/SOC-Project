"""
SOAR Playbook

공격 유형에 따라 수행해야 할 대응 절차를 정의한다.
"""

PLAYBOOKS = {

    "SQL Injection Response": [
        "공격 IP 차단",
        "웹 서버 Access Log 분석",
        "DB Query Log 분석",
        "WAF 정책 점검"
    ],

    "Command Injection Response": [
        "공격 IP 차단",
        "Shell 실행 기록 확인",
        "cron 변경 여부 확인",
        "권한 상승 여부 조사"
    ],

    "Malicious File Upload Response": [
        "공격 IP 차단",
        "업로드 파일 격리",
        "웹쉘 존재 여부 확인",
        "백신 검사 수행"
    ],

    "Directory Traversal Investigation": [
        "웹 로그 분석",
        "민감 파일 접근 여부 확인",
        "권한 설정 점검"
    ],

    "Cross-Site Scripting Investigation": [
        "입력값 검증 확인",
        "출력 인코딩 확인",
        "브라우저 로그 분석"
    ],

    "DDoS Response": [
        "공격 트래픽 확인",
        "방화벽 차단 정책 적용",
        "네트워크 사용량 분석"
    ],

    "ARP Spoofing Investigation": [
        "ARP Table 확인",
        "MAC 주소 확인",
        "스위치 보안 정책 점검"
    ],

    "File Inclusion Investigation": [
        "웹 서버 로그 확인",
        "파일 접근 권한 점검",
        "애플리케이션 설정 확인"
    ],

    "Brute Force Monitoring": [
        "로그인 실패 횟수 확인",
        "계정 잠금 정책 확인",
        "인증 로그 분석"
    ],

    "Open Redirect Investigation": [
        "Redirect URL 검증",
        "애플리케이션 코드 확인"
    ],

    "CSRF Investigation": [
        "CSRF Token 적용 여부 확인",
        "세션 정책 점검"
    ],

    "CAPTCHA Policy Review": [
        "CAPTCHA 정책 확인",
        "자동화 공격 여부 분석"
    ],

    "Port Scan Monitoring": [
        "포트 스캔 지속 여부 확인",
        "방화벽 로그 분석"
    ]
}


def get_playbook(playbook_name: str):
    """
    Playbook 이름으로 대응 절차를 반환한다.
    """

    return PLAYBOOKS.get(
        playbook_name,
        ["등록된 Playbook이 없습니다."]
    )
