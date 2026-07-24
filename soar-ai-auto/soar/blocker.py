import paramiko
import threading
import time
import json
import os
from soar.policy import POLICY
from datetime import datetime

# Ubuntu1 Gateway 서버 접속 정보
GATEWAY_HOST = "10.30.30.1"
GATEWAY_PORT = 22
GATEWAY_USERNAME = "soc"
GATEWAY_PASSWORD = "qhdks12"

BLOCK_DURATION_BY_ATTACK = {
    "sql_injection": 60,
    "command_injection": 60,
    "file_upload": 60,
    "file_inclusion": 45,
    "directory_traversal": 30,
    "ddos": 45,
    "arp_spoofing": 45,
    "port_scanning": 20,
    "xss": 20,
    "session_hijacking": 20,
    "open_redirect": 15,
    "csrf": 15,
    "brute_force": 15,
    "insecure_captcha": 10,
}
DEFAULT_BLOCK_DURATION = 15

PROTECTED_IPS = {
    "10.30.30.10",
    "10.30.30.1",
    "10.20.20.10",
    "10.20.20.1"
}

# 재부팅/재시작 이후 규칙을 유지시키는 명령 (게이트웨이에 netfilter-persistent 설치 필요)
PERSIST_COMMAND = "netfilter-persistent save"

# 앱 상태(차단 목록/승인 대기)를 저장하는 파일. 컨테이너 재시작에도 유지되도록
# docker-compose.yml에서 이 경로를 볼륨 마운트해야 함 (아래 설명 참고)
STATE_FILE = "/app/data/state.json"

blocked_ips = {}        # {src_ip: {"predicted_label":.., "blocked_at":.., "type":"temporary"/"permanent"}}
pending_approvals = {}  # {src_ip: {"predicted_label":.., "requested_at":..}}
lock = threading.Lock()


def load_state():
    """앱이 시작될 때 저장해둔 상태를 불러온다."""
    global blocked_ips, pending_approvals
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                blocked_ips.update(data.get("blocked_ips", {}))
                pending_approvals.update(data.get("pending_approvals", {}))
            print(f"[상태 로드] blocked={len(blocked_ips)}개, pending={len(pending_approvals)}개")
        except Exception as e:
            print(f"[상태 로드 실패] {e}")


def save_state():
    """현재 상태를 파일로 저장한다 (재시작해도 목록이 남도록)."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with lock:
        data = {
            "blocked_ips": blocked_ips,
            "pending_approvals": pending_approvals,
        }
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[상태 저장 실패] {e}")


load_state()


def generate_block_command(src_ip: str) -> str:
    return (
        f"iptables -I FORWARD 1 "
        f"-s {src_ip} "
        f"-m comment --comment SOAR_TEMP_BLOCK "
        f"-j DROP"
    )


def generate_unblock_command(src_ip: str) -> str:
    return (
        f"iptables -D FORWARD "
        f"-s {src_ip} "
        f"-m comment --comment SOAR_TEMP_BLOCK "
        f"-j DROP"
    )


def should_block(predicted_label: str) -> bool:
    blockable_attacks = {
        "sql_injection",
        "xss",
        "directory_traversal",
        "command_injection",
        "brute_force",
    }
    return predicted_label in blockable_attacks


def execute_block_on_gateway(command: str) -> dict:
    """Ubuntu1 Gateway에 SSH로 접속해서 명령을 실행한다."""
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


def check_ip_blocked_on_gateway(src_ip: str):
    """게이트웨이의 실제 iptables에 이 IP에 대한 SOAR 차단 규칙이 있는지 확인한다."""
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
        cmd = f"iptables -L FORWARD -n | grep {src_ip} | grep SOAR_TEMP_BLOCK"
        stdin, stdout, stderr = client.exec_command(f"sudo -S {cmd}")
        stdin.write(GATEWAY_PASSWORD + "\n")
        stdin.flush()
        output = stdout.read().decode().strip()
        client.close()
        return bool(output)
    except Exception as e:
        print(f"[상태확인 실패] {src_ip} - {e}")
        return None


def sync_ip_status(src_ip: str):
    """
    앱이 기억하는 차단 상태와 게이트웨이의 실제 iptables 상태를 비교해서
    다르면 앱 쪽을 실제 상태에 맞게 자동으로 고친다.
    """
    actually_blocked = check_ip_blocked_on_gateway(src_ip)
    if actually_blocked is None:
        print(f"[동기화 보류] {src_ip} - 게이트웨이 상태 조회 실패")
        return

    with lock:
        app_thinks_blocked = src_ip in blocked_ips

        if actually_blocked and not app_thinks_blocked:
            blocked_ips[src_ip] = {
                "predicted_label": "unknown",
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "permanent",
            }
            print(f"[동기화] {src_ip} - 실제로 차단되어 있어서 앱 상태를 맞춤")
            changed = True
        elif not actually_blocked and app_thinks_blocked:
            blocked_ips.pop(src_ip, None)
            pending_approvals.pop(src_ip, None)
            print(f"[동기화] {src_ip} - 실제로는 차단 안 되어 있어서 앱 상태를 초기화함 (재부팅 등으로 규칙 유실 추정)")
            changed = True
        else:
            changed = False

    if changed:
        save_state()


def temp_block_ip(src_ip: str, predicted_label: str) -> str:
    if src_ip in PROTECTED_IPS:
        print(f"[보호] {src_ip} 는 관리 IP이므로 차단하지 않습니다.")
        return "protected_ip"

    # 진행 전에 실제 방화벽 상태와 앱 메모리를 자동으로 맞춘다
    sync_ip_status(src_ip)

    policy = POLICY.get(predicted_label)
    if not policy:
        print(f"[정책 없음] {predicted_label}")
        return "policy_not_found"

    action = policy["action"]
    duration = policy.get("duration", 0)

    with lock:
        if src_ip in blocked_ips:
            return "already_blocked"
        if src_ip in pending_approvals:
            return "already_pending_approval"

    if action == "permanent":
        with lock:
            pending_approvals[src_ip] = {
                "predicted_label": predicted_label,
                "requested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        save_state()
        print(f"[승인 대기] {src_ip} - 영구 차단 요청됨 (공격: {predicted_label})")
        return "permanent_pending_approval"

    block_command = generate_block_command(src_ip)
    result = execute_block_on_gateway(block_command)

    if not result["success"]:
        print(f"[차단 실패] {result}")
        return "block_failed"

    with lock:
        blocked_ips[src_ip] = {
            "predicted_label": predicted_label,
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "temporary",
        }
    save_state()

    print(
        f"[차단] IP={src_ip}, 공격={predicted_label}, 정책={action}, "
        f"시간={duration}초, 결과={result}"
    )

    def release_after_delay():
        time.sleep(duration)
        unblock_command = generate_unblock_command(src_ip)
        unblock_result = execute_block_on_gateway(unblock_command)
        with lock:
            blocked_ips.pop(src_ip, None)
        save_state()
        print(f"[해제] {src_ip} - 차단 해제됨 / {unblock_result}")

    threading.Thread(target=release_after_delay, daemon=True).start()

    return f"{action}_block_started"


def approve_permanent_block(src_ip: str) -> dict:
    """관리자가 승인하면 iptables 영구 차단을 실행하고, 재부팅에도 남도록 저장한다."""
    with lock:
        if src_ip not in pending_approvals:
            return {"success": False, "message": "승인 대기 중인 요청이 없습니다."}
        request_info = pending_approvals[src_ip]

    result = execute_block_on_gateway(generate_block_command(src_ip))

    if result["success"]:
        # 게이트웨이가 재부팅되어도 이 규칙이 다시 로드되도록 저장
        execute_block_on_gateway(PERSIST_COMMAND)

    with lock:
        pending_approvals.pop(src_ip, None)
        if result["success"]:
            blocked_ips[src_ip] = {
                "predicted_label": request_info.get("predicted_label", "unknown"),
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "permanent",
            }
    save_state()

    print(f"[영구 차단 승인 완료] {src_ip} - {result}")
    return {"success": result["success"], "message": result["message"]}


def reject_permanent_block(src_ip: str) -> dict:
    with lock:
        if src_ip not in pending_approvals:
            return {"success": False, "message": "승인 대기 중인 요청이 없습니다."}
        pending_approvals.pop(src_ip, None)
    save_state()
    print(f"[영구 차단 거부] {src_ip}")
    return {"success": True, "message": "요청이 거부되었습니다."}


def unblock_ip(src_ip: str) -> dict:
    """차단 목록에 있는 IP를 수동으로 해제한다 (실제 iptables 삭제 + 저장 + 앱 상태 갱신)."""
    with lock:
        if src_ip not in blocked_ips:
            return {"success": False, "message": "차단 목록에 없는 IP입니다."}

    result = execute_block_on_gateway(generate_unblock_command(src_ip))

    if result["success"]:
        execute_block_on_gateway(PERSIST_COMMAND)
        with lock:
            blocked_ips.pop(src_ip, None)
        save_state()
        print(f"[차단 해제] {src_ip}")
    else:
        print(f"[차단 해제 실패] {src_ip} - {result}")

    return {"success": result["success"], "message": result["message"]}


def get_pending_approvals() -> dict:
    with lock:
        return dict(pending_approvals)


def list_blocked_ips() -> dict:
    with lock:
        return dict(blocked_ips)
