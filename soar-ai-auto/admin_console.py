"""
관리자용 승인/차단관리 콘솔
- 백그라운드에서 새로운 영구 차단 승인 요청을 계속 감시하고 화면에 알려준다.
- 메인 화면에서는 명령어로 승인/거부/목록조회/차단해제를 수행한다.
"""
import threading
import time
import requests
import os
from datetime import datetime

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
                print("\n")
                print("+" + "-" * 68 + "+")
                print("|{:^68}|".format("🚨 NEW APPROVAL REQUEST"))
                print("+" + "-" * 68 + "+")
                print(f"| Source IP : {src_ip:<52}|")
                print(f"| Attack    : {info['predicted_label']:<52}|")
                print(f"| Time      : {info['requested_at']:<52}|")
                print("+" + "-" * 68 + "+")
                print("Press Enter to return to Dashboard...", flush=True)
        # 처리 완료된 건 seen 목록에서도 지워서, 나중에 같은 IP가 다시 뜨면 또 알림 가능하게
        seen_pending.intersection_update(pending.keys())
        time.sleep(CHECK_INTERVAL_SECONDS)


LINE = "=" * 70

# ANSI Color
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"


def color_level(level):
    level = str(level).upper()
    if level == "LOW":
        return GREEN + level + RESET
    elif level == "MEDIUM":
        return YELLOW + level + RESET
    elif level == "HIGH":
        return RED + level + RESET
    elif level == "CRITICAL":
        return BOLD + RED + level + RESET
    return level


def clear():
    os.system("clear")


def get_pending():
    try:
        res = requests.get(f"{SOAR_API_URL}/pending-approvals", timeout=5)
        return res.json()
    except:
        return {}


def get_blocked():
    try:
        res = requests.get(f"{SOAR_API_URL}/blocked-ips", timeout=5)
        return res.json()
    except:
        return {}


def get_medium():
    try:
        res = requests.get(f"{SOAR_API_URL}/medium-alerts", timeout=5)
        return res.json()
    except:
        return []


def get_history():
    try:
        res = requests.get(f"{SOAR_API_URL}/history", timeout=5)
        data = res.json()
        if isinstance(data, dict):
            return data.get("history", "")
        return str(data)
    except:
        return "History unavailable."


def get_dashboard():
    pending = get_pending()
    blocked = get_blocked()
    medium = get_medium()
    history = get_history()

    low = 0
    medium_cnt = 0
    high = 0
    critical = 0
    total = 0
    for line in history.splitlines():
        u = line.upper()
        if "LOW" in u:
            low += 1
            total += 1
        elif "MEDIUM" in u:
            medium_cnt += 1
            total += 1
        elif "HIGH" in u:
            high += 1
            total += 1
        elif "CRITICAL" in u:
            critical += 1
            total += 1

    permanent_cnt = sum(1 for v in blocked.values() if v.get("type") == "permanent")
    temporary_cnt = sum(1 for v in blocked.values() if v.get("type") == "temporary")

    return {
        "pending": len(pending),
        "blocked": len(blocked),
        "permanent": permanent_cnt,
        "temporary": temporary_cnt,
        "medium_alerts": len(medium),
        "total": total,
        "low": low,
        "medium": medium_cnt,
        "high": high,
        "critical": critical,
    }


def print_dashboard():
    clear()
    stat = get_dashboard()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("+" + "-" * 68 + "+")
    print("|{:^68}|".format("AI SOAR SECURITY OPERATION CENTER"))
    print("|{:^68}|".format(now))
    print("+" + "-" * 68 + "+")
    print("| Pending Approval : {:<48}|".format(stat["pending"]))
    print("| Blocked IP (전체) : {:<47}|".format(stat["blocked"]))
    print("|   - 영구 차단     : {:<47}|".format(stat["permanent"]))
    print("|   - 임시 차단     : {:<47}|".format(stat["temporary"]))
    print("| Medium Alerts     : {:<47}|".format(stat["medium_alerts"]))
    print("| Today's Incident  : {:<47}|".format(stat["total"]))
    print("+" + "-" * 68 + "+")
    print(
        "| LOW {:>5} | MEDIUM {:>5} | {}HIGH{:>5}{} | {}CRITICAL{:>5}{} |".format(
            stat["low"],
            stat["medium"],
            RED,
            stat["high"],
            RESET,
            BOLD + RED,
            stat["critical"],
            RESET,
        )
    )
    print("+" + "-" * 68 + "+")
    print("| [1] Pending Approval{:45}|".format(""))
    print("| [2] Blocked IP (영구/임시 구분){:34}|".format(""))
    print("| [3] Incident History{:45}|".format(""))
    print("| [4] Refresh{:54}|".format(""))
    print("| [5] Medium Alerts{:48}|".format(""))
    print("| [0] Exit{:57}|".format(""))
    print("+" + "-" * 68 + "+")


def show_pending():
    pending = get_pending()
    if not pending:
        print("\n현재 승인 대기 중인 요청이 없습니다.")
        input("\nEnter...")
        return
    items = list(pending.items())
    while True:
        clear()
        print("+" + "-" * 68 + "+")
        print("|{:^68}|".format("Pending Approval"))
        print("+" + "-" * 68 + "+")
        print("{:<4}{:<18}{:<20}{}".format(
            "No",
            "Source IP",
            "Attack",
            "Requested Time"
        ))
        print("-" * 68)
        print(f"\nTotal Pending : {len(items)}\n")
        for idx, (ip, info) in enumerate(items, start=1):
            print(
                "{:<4}{:<18}{:<20}{}".format(
                    idx,
                    ip,
                    info["predicted_label"],
                    info["requested_at"],
                )
            )
        print(LINE)
        print("번호 입력 : 승인/거부")
        print("0 : 뒤로")
        print(LINE)
        try:
            sel = int(input("선택 > "))
        except ValueError:
            continue
        if sel == 0:
            return
        if sel < 1 or sel > len(items):
            continue
        ip, info = items[sel - 1]
        while True:
            ans = input(f"\n[{ip}]  (a=Approve / r=Reject / b=Back) > ").lower()
            if ans == "a":
                do_approve(ip)
                input("\nEnter...")
                return
            elif ans == "r":
                do_reject(ip)
                input("\nEnter...")
                return
            elif ans == "b":
                break


def show_blocked():
    """영구 차단 목록과 임시 차단 목록을 구분해서 보여준다."""
    blocked = get_blocked()
    if not blocked:
        print("\n현재 차단된 IP가 없습니다.")
        input("\nEnter...")
        return

    permanent = {ip: info for ip, info in blocked.items() if info.get("type") == "permanent"}
    temporary = {ip: info for ip, info in blocked.items() if info.get("type") == "temporary"}
    items = list(permanent.items()) + list(temporary.items())
    permanent_count = len(permanent)

    while True:
        clear()
        print("+" + "-" * 68 + "+")
        print("|{:^68}|".format("Blocked IP"))
        print("+" + "-" * 68 + "+")
        print("{:<4}{:<18}{:<20}{}".format(
            "No",
            "Source IP",
            "Attack",
            "Blocked Time"
        ))
        print("-" * 68)

        if permanent:
            print(f"\n[영구 차단 목록] ({permanent_count}개)")
            for idx, (ip, info) in enumerate(items[:permanent_count], start=1):
                print(
                    "{:<4}{:<18}{:<20}{}".format(
                        idx,
                        ip,
                        info.get("predicted_label", "-"),
                        info.get("blocked_at", "-"),
                    )
                )

        if temporary:
            print(f"\n[임시 차단 목록] ({len(temporary)}개)")
            for idx, (ip, info) in enumerate(items[permanent_count:], start=permanent_count + 1):
                print(
                    "{:<4}{:<18}{:<20}{}".format(
                        idx,
                        ip,
                        info.get("predicted_label", "-"),
                        info.get("blocked_at", "-"),
                    )
                )

        print(f"\nTotal Blocked : {len(items)}\n")
        print(LINE)
        print("번호 입력 : 차단 해제")
        print("0 : 뒤로")
        print(LINE)
        try:
            sel = int(input("선택 > "))
        except ValueError:
            continue
        if sel == 0:
            return
        if sel < 1 or sel > len(items):
            continue
        ip = items[sel - 1][0]
        yn = input(f"\n{ip} 차단을 해제하시겠습니까? (y/n) ")
        if yn.lower() == "y":
            do_unblock(ip)
            input("\nEnter...")
            return


def show_medium():
    """MEDIUM 등급으로 탐지되어 콘솔 확인이 필요한 목록을 보여준다."""
    items = get_medium()
    clear()
    print("+" + "-" * 68 + "+")
    print("|{:^68}|".format("Medium Alerts (확인 필요, 차단 안 됨)"))
    print("+" + "-" * 68 + "+")
    if not items:
        print("MEDIUM 확인 목록이 비어 있습니다.")
    else:
        print("{:<4}{:<18}{:<20}{}".format("No", "Source IP", "Attack", "Detected Time"))
        print("-" * 68)
        for idx, e in enumerate(items, start=1):
            print(
                "{:<4}{:<18}{:<20}{}".format(
                    idx,
                    e.get("src_ip", "-"),
                    f"{e.get('predicted_label', '-')}({e.get('score', '-')})",
                    e.get("detected_at", "-"),
                )
            )
    print("+" + "-" * 68 + "+")
    input("Enter...")


def show_history():
    clear()
    print("+" + "-" * 68 + "+")
    print("|{:^68}|".format("Incident History"))
    print("+" + "-" * 68 + "+")
    history = get_history()

    if not history.strip():
        print("No incident history.")
    else:
        lines = history.splitlines()
        # 최근 20줄만 출력
        for line in lines[-20:]:
            print(line)

    print("+" + "-" * 68 + "+")
    input("Enter...")


def do_approve(src_ip):
    result = requests.post(f"{SOAR_API_URL}/approve", json={"src_ip": src_ip}).json()
    print(f"[승인 완료] {result}")


def do_reject(src_ip):
    result = requests.post(f"{SOAR_API_URL}/reject", json={"src_ip": src_ip}).json()
    print(f"[거부 완료] {result}")


def do_unblock(src_ip):
    result = requests.post(f"{SOAR_API_URL}/unblock", json={"src_ip": src_ip}).json()
    print(f"[차단 해제] {result}")


def main():
    watcher = threading.Thread(target=watch_pending, daemon=True)
    watcher.start()
    while True:
        print_dashboard()
        try:
            menu = input("Menu > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n종료합니다.")
            break
        if menu == "1":
            show_pending()
        elif menu == "2":
            show_blocked()
        elif menu == "3":
            show_history()
        elif menu == "4":
            continue
        elif menu == "5":
            show_medium()
        elif menu == "0":
            print("종료합니다.")
            break
        else:
            input("\n잘못된 메뉴입니다. Enter...")


if __name__ == "__main__":
    main()
