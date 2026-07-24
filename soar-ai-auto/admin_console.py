"""
관리자용 승인/차단관리 콘솔
- 백그라운드에서 새로운 영구 차단 승인 요청을 계속 감시하고 화면에 알려준다.
- 메인 화면에서는 명령어로 승인/거부/목록조회/차단해제를 수행한다.
"""
import threading
import time
import requests

SOAR_API_URL = "http://127.0.0.1:8000"
CHECK_INTERVAL_SECONDS = 5

seen_pending = set()  # 이미 화면에 알려준 승인 요청 (중복 알림 방지)


def watch_pending():
    """백그라운드에서 새 승인 요청이 뜨면 화면에 출력만 한다 (입력을 막지 않음)."""
    while True:
        try:
            res = requests.get(f"{SOAR_API_URL}/pending-approvals", timeout=5)
            pending = res.json()
        except requests.RequestException as e:
            print(f"\n[에러] 서버 연결 실패: {e}")
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        for src_ip, info in pending.items():
            if src_ip not in seen_pending:
                seen_pending.add(src_ip)
                print("\n" + "=" * 60)
                print("⚠️  새로운 영구 차단 승인 요청 도착")
                print(f"IP        : {src_ip}")
                print(f"공격 유형  : {info['predicted_label']}")
                print(f"요청 시간  : {info['requested_at']}")
                print("=" * 60)
                print("메뉴에서 'approve <ip>' 또는 'reject <ip>' 로 처리하세요.\n> ", end="", flush=True)

        # 처리 완료된 건 seen 목록에서도 지워서, 나중에 같은 IP가 다시 뜨면 또 알림 가능하게
        seen_pending.intersection_update(pending.keys())

        time.sleep(CHECK_INTERVAL_SECONDS)


def show_pending():
    try:
        res = requests.get(f"{SOAR_API_URL}/pending-approvals", timeout=5)
        pending = res.json()
    except requests.RequestException as e:
        print(f"[에러] 서버 연결 실패: {e}")
        return

    if not pending:
        print("현재 승인 대기 중인 요청이 없습니다.")
        return

    print("\n[승인 대기 목록]")
    for src_ip, info in pending.items():
        print(f"  - {src_ip} | 공격: {info['predicted_label']} | 요청시간: {info['requested_at']}")


def show_blocked():
    try:
        res = requests.get(f"{SOAR_API_URL}/blocked-ips", timeout=5)
        blocked = res.json()
    except requests.RequestException as e:
        print(f"[에러] 서버 연결 실패: {e}")
        return

    if not blocked:
        print("현재 차단 중인 IP가 없습니다.")
        return

    print("\n[차단 목록]")
    for src_ip, info in blocked.items():
        print(
            f"  - {src_ip} | 유형: {info.get('type')} | "
            f"공격: {info.get('predicted_label')} | 차단시각: {info.get('blocked_at')}"
        )


def do_approve(src_ip):
    result = requests.post(f"{SOAR_API_URL}/approve", json={"src_ip": src_ip}).json()
    print(f"[승인 완료] {result}")


def do_reject(src_ip):
    result = requests.post(f"{SOAR_API_URL}/reject", json={"src_ip": src_ip}).json()
    print(f"[거부 완료] {result}")


def do_unblock(src_ip):
    result = requests.post(f"{SOAR_API_URL}/unblock", json={"src_ip": src_ip}).json()
    print(f"[차단 해제] {result}")


def print_help():
    print("""
사용 가능한 명령어
------------------------------------------------
pending                 : 승인 대기 목록 보기
blocked                 : 현재 차단 목록 보기
approve <ip>            : 해당 IP 영구 차단 승인
reject  <ip>            : 해당 IP 승인 요청 거부
unblock <ip>            : 해당 IP 차단 해제
help                    : 명령어 도움말
quit                    : 종료
------------------------------------------------
""")


def main():
    print("=" * 60)
    print("        영구 차단 승인 / 관리 콘솔 시작")
    print("=" * 60)
    print_help()

    watcher = threading.Thread(target=watch_pending, daemon=True)
    watcher.start()

    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n종료합니다.")
            break

        if not cmd:
            continue

        parts = cmd.split()
        action = parts[0].lower()

        if action == "pending":
            show_pending()
        elif action == "blocked":
            show_blocked()
        elif action == "approve" and len(parts) == 2:
            do_approve(parts[1])
        elif action == "reject" and len(parts) == 2:
            do_reject(parts[1])
        elif action == "unblock" and len(parts) == 2:
            do_unblock(parts[1])
        elif action in ("help", "?"):
            print_help()
        elif action in ("quit", "exit"):
            print("종료합니다.")
            break
        else:
            print("알 수 없는 명령어입니다. 'help'를 입력해서 사용법을 확인하세요.")


if __name__ == "__main__":
    main()
