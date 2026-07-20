import paramiko
import threading
import time
from soar.policy import POLICY

# Ubuntu1 Gateway 서버 접속 정보
GATEWAY_HOST = "10.30.30.100"       # Ubuntu1 Gateway의 실제 IP
GATEWAY_PORT = 22
GATEWAY_USERNAME = "soc"
GATEWAY_PASSWORD = "qhdks12"

# 공격 유형별 임시 차단 시간(초)
BLOCK_DURATION_BY_ATTACK = {
    # 서버 장악급 - 매우 높은 위험도
    "sql_injection": 60,
    "command_injection": 60,
    "file_upload": 60,

    # 시스템/파일 접근 - 높은 위험도
    "file_inclusion": 45,
    "directory_traversal": 30,

    # 네트워크 레벨 위협
    "ddos": 45,
    "arp_spoofing": 45,
    "port_scanning": 20,

    # 클라이언트/세션 관련 - 중간 위험도
    "xss": 20,
    "session_hijacking": 20,
    "open_redirect": 15,
    "csrf": 15,

    # 인증 관련 - 반복성 위협
    "brute_force": 15,
    "insecure_captcha": 10,
}
DEFAULT_BLOCK_DURATION = 15   # 목록에 없는 유형이면 기본값 (안전장치)

# 자동 차단에서 제외할 관리 IP
PROTECTED_IPS = {
    "10.30.30.10",   # Wazuh Manager
    "10.30.30.1",  # Gateway
    }
# 지금 차단 중인 IP들을 기억해두는 목록 (중복 차단 방지용)
blocked_ips = set()
lock = threading.Lock()



def generate_block_command(src_ip: str) -> str:
    """게이트웨이를 통과하는 공격 IP를 임시 차단한다."""
    return (
        f"iptables -I FORWARD 1 " 
        f"-s {src_ip} " 
        f"-m comment --comment SOAR_TEMP_BLOCK "
        f"-j DROP"
    )


def generate_unblock_command(src_ip: str) -> str:
    """SOAR가 추가한 임시 차단 정책을 삭제한다."""
    return (
        f"iptables -D FORWARD "
        f"-s {src_ip} "
        f"-m comment --comment SOAR_TEMP_BLOCK "
        f"-j DROP"
        )


def should_block(predicted_label: str) -> bool:
    """이 공격 유형이 자동 차단 대상인지 판단"""
    blockable_attacks = {
        "sql_injection",
        "xss",
        "directory_traversal",
        "command_injection",
        "brute_force",
    }
    return predicted_label in blockable_attacks


def execute_block_on_gateway(command: str) -> dict:
    """Ubuntu1 Gateway에 SSH로 접속해서 실제로 iptables 명령을 실행한다"""
    try:
        print(f"[SSH HOST] {GATEWAY_HOST}")
        print(f"[SSH CMD] {command}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=GATEWAY_HOST,
            port=GATEWAY_PORT,
            username=GATEWAY_USERNAME,
            password=GATEWAY_PASSWORD,
            timeout=5,
        )
        stdin, stdout, stderr = client.exec_command(f"sudo -S {command}")
        stdin.write(GATEWAY_PASSWORD + "\n")
        stdin.flush()
        
        stdout_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()
        
        client.close()

        print(f"[STDOUT] {stdout_output}")
        print(f"[STDERR] {stderr_output}")

        if stderr_output and "password" not in stderr_output.lower():
            return {"success": False, "message": stderr_output}
        return {"success": True, "message": stdout_output}
    except Exception as e:
        return {"success": False, "message": str(e)}


def temp_block_ip(src_ip: str, predicted_label: str) -> str:
    """
    공격 IP를 임시 차단한다.
    이미 차단 중이면 아무것도 하지 않고, 아니면 새로 10초 차단을 시작한다.
    반환값: 이번 요청에서 실제로 무슨 일이 일어났는지
    """
    # 관리 IP는 차단하지 않음
    if src_ip in PROTECTED_IPS:
        print(f"[보호] {src_ip} 는 관리 IP이므로 차단하지 않습니다.")
        return "protected_ip"

    # 공격 유형에 따른 정책 조회
    policy = POLICY.get(predicted_label)

    if not policy:
        print(f"[정책 없음] {predicted_label}")
        return "policy_not_found"

    action = policy["action"]
    duration = policy.get("duration", 0)

    with lock:
        if src_ip in blocked_ips:
            # 이미 차단 규칙이 걸려있으니 새로 걸 필요 없음
            return "already_blocked"
    block_command = generate_block_command(src_ip)
    result = execute_block_on_gateway(block_command)   
    
    if not result["success"]:
        print(f"[차단 실패] {result}")
        return "block_failed"

    with lock:
        blocked_ips.add(src_ip) 

    print(
         f"[차단] "
         f"IP={src_ip}, "
         f"공격={predicted_label}, "
         f"정책={action}, "
         f"시간={duration}초, "
         f"결과={result}"
    )

    if action == "permanent":
        return "permanent_block_started"
    # 정책에 정의된 시간(duration) 후 자동 해제
    def release_after_delay():
        time.sleep(duration)
        unblock_command = generate_unblock_command(src_ip)
        unblock_result = execute_block_on_gateway(unblock_command)
        with lock:
            blocked_ips.discard(src_ip)
        print(f"[해제] {src_ip} - 차단 해제됨 / {unblock_result}")

    threading.Thread(target=release_after_delay, daemon=True).start()

    return f"{action}_block_started"
