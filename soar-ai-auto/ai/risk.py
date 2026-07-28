"""
SOAR-AI-AUTO Risk Scoring Engine

OWASP Risk Rating Methodology(Likelihood x Impact)의 핵심 개념을 참고하여,
실시간 자동 대응(SOAR)에 적합하도록 단순화한 자체 채점 체계.

OWASP 원본은 8개 Likelihood 요소 x 8개 Impact 요소를 각각 평가해 곱하는
방식이지만, 본 프로젝트는 실시간 처리를 위해 아래처럼 가산점 방식으로
단순화했다.

    Score = Base(공격 유형 고유 위험도)
          + Likelihood(동일 IP 반복 횟수)          <- OWASP Likelihood 대응
          + Multi-Stage(Kill Chain 연쇄 여부)       <- OWASP Likelihood 대응
          + Business Impact(공격 대상 URL 중요도)   <- OWASP Business Impact 대응
          + Sensitive Target(민감 파일 직접 접근)   <- OWASP Technical Impact 대응
          + Post-Exploitation(침투 성공 흔적)       <- OWASP Technical Impact 대응
          (최대 100점, 초과분은 100으로 절삭)

등급 구간: LOW(0~29) / MEDIUM(30~59) / HIGH(60~79) / CRITICAL(80~100)
"""
import re

# ── 1. Base Score : 공격 유형 자체의 기본 위험도 ──────────────
# OWASP의 "취약점이 악용됐을 때의 기술적 영향" 중 공격 유형별 평균적 심각도를
# 고정값으로 미리 반영한 것 (매 요청마다 8개 항목을 다시 평가하지 않기 위함)
BASE_SCORE = {
    "port_scanning": 10,
    "ping_sweep": 10,
    "insecure_captcha": 15,
    "brute_force": 20,
    "csrf": 20,
    "open_redirect": 20,
    "xss": 40,
    "arp_spoofing": 45,
    "session_hijacking": 45,
    "directory_traversal": 50,
    "file_inclusion": 55,
    "ddos": 55,
    "sql_injection": 70,
    "file_upload": 80,
    "command_injection": 90,
}

PLAYBOOK_BY_ATTACK = {
    "sql_injection": "SQL Injection Response",
    "command_injection": "Command Injection Response",
    "file_upload": "Malicious File Upload Response",
    "directory_traversal": "Directory Traversal Investigation",
    "file_inclusion": "File Inclusion Investigation",
    "xss": "Cross-Site Scripting Investigation",
    "ddos": "DDoS Response",
    "arp_spoofing": "ARP Spoofing Investigation",
    "session_hijacking": "Session Hijacking Investigation",
    "brute_force": "Brute Force Monitoring",
    "open_redirect": "Open Redirect Investigation",
    "csrf": "CSRF Investigation",
    "insecure_captcha": "CAPTCHA Policy Review",
    "port_scanning": "Port Scan Monitoring",
    "ping_sweep": "Ping Sweep Monitoring",
}

RECOMMENDATION_BY_ATTACK = {
    "sql_injection": "공격 IP를 차단하고 웹 서버 및 DB 로그를 확인하세요.",
    "command_injection": "공격 IP를 차단하고 서버 명령 실행 흔적을 조사하세요.",
    "file_upload": "업로드된 파일을 검사하고 웹쉘 여부를 확인하세요.",
    "directory_traversal": "민감한 파일 접근 여부와 웹 서버 로그를 확인하세요.",
    "file_inclusion": "웹 애플리케이션 파일 접근 정책을 점검하세요.",
    "xss": "입력값 검증 및 출력 인코딩 정책을 점검하세요.",
    "ddos": "방화벽 및 네트워크 트래픽을 분석하세요.",
    "arp_spoofing": "ARP 테이블과 스위치 보안 설정을 확인하세요.",
    "session_hijacking": "세션 토큰 재발급 정책과 쿠키 보안 속성(HttpOnly, Secure)을 점검하세요.",
    "brute_force": "계정 잠금 정책과 로그인 실패 기록을 확인하세요.",
    "open_redirect": "리다이렉트 대상 URL 검증 로직을 확인하세요.",
    "csrf": "CSRF Token 적용 여부를 확인하세요.",
    "insecure_captcha": "CAPTCHA 정책을 강화하세요.",
    "port_scanning": "지속적인 포트 스캔 여부를 모니터링하세요.",
    "ping_sweep": "지속적인 Ping Sweep 여부를 모니터링하세요.",
}


# ── 2. Likelihood : 동일 IP의 반복 공격 횟수 (OWASP Likelihood 요소 대응) ──
def _likelihood_score(event_count: int) -> int:
    if event_count >= 50:
        return 15
    if event_count >= 20:
        return 10
    if event_count >= 5:
        return 5
    return 0


# ── 3. Multi-Stage : Kill Chain 상 연쇄 공격 패턴 (OWASP Likelihood 요소 대응) ──
MULTI_STAGE_PATTERNS = [
    (("port_scanning", "sql_injection"), 15),
    (("port_scanning", "directory_traversal"), 15),
    (("port_scanning", "brute_force"), 10),
    (("directory_traversal", "command_injection"), 20),
    (("brute_force", "command_injection"), 20),
    (("sql_injection", "file_upload"), 20),
    (("file_inclusion", "command_injection"), 20),
]


def _multi_stage_score(attack_flow: list) -> int:
    score = 0
    flow_pairs = list(zip(attack_flow, attack_flow[1:]))
    for pattern, bonus in MULTI_STAGE_PATTERNS:
        if pattern in flow_pairs:
            score += bonus
    if len(set(attack_flow)) >= 3:
        score += 15
    return score


# ── 4. Business Impact : 공격 대상 URL의 자산 중요도 (OWASP Business Impact 대응) ──
BUSINESS_IMPACT_URL = [
    ("/api/admin", 15),
    ("/admin", 15),
    ("/login", 10),
]

_URL_PATTERN = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)')


def _extract_url(full_log: str) -> str:
    """접근 로그 문자열에서 실제 요청 경로만 뽑아낸다."""
    if not full_log:
        return ""
    match = _URL_PATTERN.search(full_log)
    return match.group(1) if match else ""


def _business_impact_score(url_path: str) -> int:
    if not url_path:
        return 0
    for path, bonus in BUSINESS_IMPACT_URL:
        if path in url_path:
            return bonus
    return 0


# ── 5. Sensitive Target : 민감 파일을 직접 노렸는가 (OWASP Technical Impact 대응) ──
# Directory Traversal/File Inclusion은 "../"만으로는 공격 성립 여부를 알 수 없고,
# 실제로 민감한 파일을 목표로 했을 때만 위험도를 추가로 반영한다.
SENSITIVE_FILE_TARGETS = ["/etc/passwd", "/etc/shadow", ".env", "id_rsa", "web.config", "wp-config.php"]


def _sensitive_target_score(predicted_label: str, full_log: str) -> int:
    if predicted_label not in ("directory_traversal", "file_inclusion"):
        return 0
    if not full_log:
        return 0
    lowered = full_log.lower()
    for target in SENSITIVE_FILE_TARGETS:
        if target in lowered:
            return 20
    return 0


# ── 6. Post-Exploitation : 실제 침투/명령 실행 흔적 (OWASP Technical Impact 대응) ──
POST_EXPLOITATION_INDICATORS = [
    "whoami", "wget ", "curl http", "nc -e", "/bin/bash -i",
    "cmd.exe", "powershell -enc", "eval(base64_decode",
]


def _post_exploitation_score(full_log: str) -> int:
    if not full_log:
        return 0
    lowered = full_log.lower()
    for indicator in POST_EXPLOITATION_INDICATORS:
        if indicator in lowered:
            return 25
    return 0


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_risk(
    predicted_label: str,
    event_count: int = 1,
    attack_flow=None,
    full_log: str = "",
) -> dict:
    """공격 유형과 탐지 컨텍스트를 바탕으로 최종 Risk Score(0~100)를 계산한다."""
    attack_flow = attack_flow or [predicted_label]
    url_path = _extract_url(full_log)

    base = BASE_SCORE.get(predicted_label, 10)
    likelihood = _likelihood_score(event_count)
    multi_stage = _multi_stage_score(attack_flow)
    business = _business_impact_score(url_path)
    sensitive = _sensitive_target_score(predicted_label, full_log)
    post_exploit = _post_exploitation_score(full_log)

    score = min(base + likelihood + multi_stage + business + sensitive + post_exploit, 100)
    level = _risk_level(score)

    return {
        "score": score,
        "risk": level,
        "playbook": PLAYBOOK_BY_ATTACK.get(predicted_label, "Unknown"),
        "recommendation": RECOMMENDATION_BY_ATTACK.get(predicted_label, "추가 분석이 필요합니다."),
        "breakdown": {
            "base": base,
            "likelihood": likelihood,
            "multi_stage": multi_stage,
            "business_impact": business,
            "sensitive_target": sensitive,
            "post_exploitation": post_exploit,
        },
    }


def get_attack_info(predicted_label: str) -> dict:
    """하위 호환용: 컨텍스트 없이 기본 점수만 계산."""
    return calculate_risk(predicted_label)
