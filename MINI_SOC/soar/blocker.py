"""
SOAR - 공격 IP 자동 차단
dry_run=True 이면 실제로 iptables를 실행하지 않고 로그만 출력한다 (테스트/발표용 안전장치).
"""

import subprocess


def block_ip(ip: str, dry_run: bool = True) -> None:
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    if dry_run:
        print(f"[SOAR][DRY-RUN] 차단 명령 (실행 안 함): {' '.join(cmd)}")
        return

    try:
        subprocess.run(cmd, check=True)
        print(f"[SOAR] IP 차단 완료: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[SOAR][ERROR] IP 차단 실패: {ip} ({e})")
    except FileNotFoundError:
        print("[SOAR][ERROR] iptables 명령을 찾을 수 없습니다. (Linux 환경에서만 동작)")
