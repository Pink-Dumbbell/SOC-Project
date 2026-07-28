import paramiko
import threading
import time
import json
import os
from soar.policy import LEVEL_POLICY
from soar.logger import log_action
from datetime import datetime

GATEWAY_HOST = "10.30.30.1"
GATEWAY_PORT = 22
GATEWAY_USERNAME = "soc"
GATEWAY_PASSWORD = "qhdks12"

PROTECTED_IPS = {
    "10.30.30.10",
    "10.30.30.1",
    "10.20.20.10",
    "10.20.20.1"
}

PERSIST_COMMAND = "netfilter-persistent save"
STATE_FILE = "/app/data/state.json"

blocked_ips = {}
pending_approvals = {}
medium_alerts = []
MEDIUM_ALERT_LIMIT = 50

lock = threading.Lock()


def load_state():
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
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with lock:
        data = {"blocked_ips": blocked_ips, "pending_approvals": pending_approvals}
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[상태 저장 실패] {e}")


load_state()


def record_medium_alert(src_ip: str, predicted_label: str, score: int) -> None:
    entry = {
        "src_ip": src_ip,
        "predicted_label": predicted_label,
        "score": score,
        "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with lock:
        medium_alerts.append(entry)
        if len(medium_alerts) > MEDIUM_ALERT_LIMIT:
            medium_alerts.pop(0)


def list_medium_alerts() -> list:
    with lock:
        return list(medium_alerts)


def generate_block_command(src_ip: str) -> str:
    return f"iptables -I FORWARD 1 -s {src_ip} -m comment --comment SOAR_TEMP_BLOCK -j DROP"


def generate_unblock_command(src_ip: str) -> str:
    return f"iptables -D FORWARD -s {src_ip} -m comment --comment SOAR_TEMP_BLOCK -j DROP"


def execute_block_on_gateway(command: str) -> dict:
    try:
        print(f"[SSH HOST] {GATEWAY_HOST}")
        print(f"[SSH CMD] {command}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=GATEWAY_HOST, port=GATEWAY_PORT,
                        username=GATEWAY_USERNAME, password=GATEWAY_PASSWORD, timeout=5)
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
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=GATEWAY_HOST, port=GATEWAY_PORT,
                        username=GATEWAY_USERNAME, password=GATEWAY_PASSWORD, timeout=5)
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
    actually_blocked = check_ip_blocked_on_gateway(src_ip)
    if actually_blocked is None:
        return
    with lock:
        app_thinks_blocked = src_ip in blocked_ips
        changed = False
        if actually_blocked and not app_thinks_blocked:
            blocked_ips[src_ip] = {
                "predicted_label": "unknown",
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "permanent",
            }
            changed = True
        elif not actually_blocked and app_thinks_blocked:
            blocked_ips.pop(src_ip, None)
            pending_approvals.pop(src_ip, None)
            changed = True
    if changed:
        save_state()


def handle_risk(src_ip: str, predicted_label: str, risk_level: str, score: int) -> str:
    """Risk Level에 따라 로그저장/MEDIUM목록등록/임시차단/영구승인요청 중 하나를 수행한다."""
    if src_ip in PROTECTED_IPS:
        print(f"[보호] {src_ip} 는 관리 IP이므로 조치하지 않습니다.")
        return "protected_ip"

    sync_ip_status(src_ip)

    policy = LEVEL_POLICY.get(risk_level)
    if not policy:
        return "policy_not_found"

    action = policy["action"]

    with lock:
        if src_ip in blocked_ips:
            return "already_blocked"
        if src_ip in pending_approvals:
            return "already_pending_approval"

    if action == "log_only":
        print(f"[로그 저장] {src_ip} - {predicted_label} (score={score}, LOW)")
        return "log_only"

    if action == "notify_only":
        record_medium_alert(src_ip, predicted_label, score)
        print(f"[관리자 확인 필요] {src_ip} - {predicted_label} (score={score}, MEDIUM)")
        return "notify_only"

    if action == "permanent":
        with lock:
            pending_approvals[src_ip] = {
                "predicted_label": predicted_label,
                "risk_level": risk_level,
                "score": score,
                "requested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        save_state()
        print(f"[승인 대기] {src_ip} - 영구 차단 요청됨 (공격: {predicted_label}, score={score})")
        return "permanent_pending_approval"

    # action == "temporary"
    duration = policy.get("duration", 900)
    result = execute_block_on_gateway(generate_block_command(src_ip))
    if not result["success"]:
        print(f"[차단 실패] {result}")
        return "block_failed"

    with lock:
        blocked_ips[src_ip] = {
            "predicted_label": predicted_label,
            "risk_level": risk_level,
            "score": score,
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "temporary",
        }
    save_state()
    print(f"[임시 차단] {src_ip} - {predicted_label} (score={score}, {risk_level}, {duration}초)")

    def release_after_delay():
        time.sleep(duration)
        unblock_result = execute_block_on_gateway(generate_unblock_command(src_ip))
        with lock:
            blocked_ips.pop(src_ip, None)
        save_state()
        log_action(src_ip, predicted_label, risk_level, "-", "temporary_block_expired")
        print(f"[해제] {src_ip} - 차단 해제됨 / {unblock_result}")

    threading.Thread(target=release_after_delay, daemon=True).start()
    return "temporary_block_started"


def approve_permanent_block(src_ip: str) -> dict:
    with lock:
        if src_ip not in pending_approvals:
            return {"success": False, "message": "승인 대기 중인 요청이 없습니다."}
        request_info = pending_approvals[src_ip]

    result = execute_block_on_gateway(generate_block_command(src_ip))
    if result["success"]:
        execute_block_on_gateway(PERSIST_COMMAND)

    with lock:
        pending_approvals.pop(src_ip, None)
        if result["success"]:
            blocked_ips[src_ip] = {
                "predicted_label": request_info.get("predicted_label", "unknown"),
                "risk_level": request_info.get("risk_level", "CRITICAL"),
                "score": request_info.get("score"),
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "permanent",
            }
    save_state()

    log_action(
        src_ip,
        request_info.get("predicted_label", "unknown"),
        request_info.get("risk_level", "CRITICAL"),
        "-",
        "permanent_block_approved" if result["success"] else "permanent_block_approve_failed",
    )

    print(f"[영구 차단 승인 완료] {src_ip} - {result}")
    return {"success": result["success"], "message": result["message"]}


def reject_permanent_block(src_ip: str) -> dict:
    with lock:
        if src_ip not in pending_approvals:
            return {"success": False, "message": "승인 대기 중인 요청이 없습니다."}
        request_info = pending_approvals[src_ip]
        pending_approvals.pop(src_ip, None)
    save_state()

    log_action(
        src_ip,
        request_info.get("predicted_label", "unknown"),
        request_info.get("risk_level", "-"),
        "-",
        "permanent_block_rejected",
    )

    print(f"[영구 차단 거부] {src_ip}")
    return {"success": True, "message": "요청이 거부되었습니다."}


def unblock_ip(src_ip: str) -> dict:
    with lock:
        if src_ip not in blocked_ips:
            return {"success": False, "message": "차단 목록에 없는 IP입니다."}
        block_info = blocked_ips[src_ip]

    result = execute_block_on_gateway(generate_unblock_command(src_ip))
    if result["success"]:
        execute_block_on_gateway(PERSIST_COMMAND)
        with lock:
            blocked_ips.pop(src_ip, None)
        save_state()
        log_action(
            src_ip,
            block_info.get("predicted_label", "unknown"),
            block_info.get("risk_level", "-"),
            "-",
            "manually_unblocked",
        )
    return {"success": result["success"], "message": result["message"]}


def get_pending_approvals() -> dict:
    with lock:
        return dict(pending_approvals)


def list_blocked_ips() -> dict:
    with lock:
        return dict(blocked_ips)
