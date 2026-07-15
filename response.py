import paramiko
import threading
import time

# Ubuntu1 Gateway 서버 접속 정보
GATEWAY_HOST = "10.30.30.100"       # Ubuntu1 Gateway의 실제 IP
GATEWAY_PORT = 22
GATEWAY_USERNAME = "soc"
GATEWAY_PASSWORD = "qhdks12"

# 지금 차단 중인 IP들을 기억해두는 목록 (중복 차단 방지용)
blocked_ips = set()
lock = threading.Lock()

BLOCK_DURATION_SECONDS = 10   # 임시 차단 유지 시간


def generate_block_command(src_ip: str) -> str:
    """공격 IP를 차단하는 iptables 명령어를 만든다"""
    return f"iptables -A INPUT -s {src_ip} -j DROP"


def generate_unblock_command(src_ip: str) -> str:
    """차단했던 IP를 다시 풀어주는 명령어를 만든다"""
    return f"iptables -D INPUT -s {src_ip} -j DROP"


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
        error_output = stderr.read().decode().strip()
        client.close()

        if error_output and "password" not in error_output.lower():
            return {"success": False, "message": error_output}
        return {"success": True, "message": "명령 실행 완료"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def temp_block_ip(src_ip: str) -> str:
    """
    공격 IP를 임시 차단한다.
    이미 차단 중이면 아무것도 하지 않고, 아니면 새로 10초 차단을 시작한다.
    반환값: 이번 요청에서 실제로 무슨 일이 일어났는지
    """
    with lock:
        if src_ip in blocked_ips:
            # 이미 차단 규칙이 걸려있으니 새로 걸 필요 없음
            return "already_blocked"
        blocked_ips.add(src_ip)

    # 여기 도달했다는 건 = 새로 차단을 걸어야 하는 상황
    block_command = generate_block_command(src_ip)
    result = execute_block_on_gateway(block_command)
    print(f"[차단] {src_ip} - {BLOCK_DURATION_SECONDS}초간 차단 시작 / {result}")

    # 별도 스레드에서 10초 대기 후 자동 해제 (메인 흐름을 막지 않기 위해)
    def release_after_delay():
        time.sleep(BLOCK_DURATION_SECONDS)
        unblock_command = generate_unblock_command(src_ip)
        unblock_result = execute_block_on_gateway(unblock_command)
        with lock:
            blocked_ips.discard(src_ip)
        print(f"[해제] {src_ip} - 차단 해제됨 / {unblock_result}")

    threading.Thread(target=release_after_delay, daemon=True).start()

    return "new_block_started"