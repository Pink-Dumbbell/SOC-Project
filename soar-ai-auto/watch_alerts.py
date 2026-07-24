import json
import time
from datetime import datetime

from config import ALERTS_FILE, CHECK_INTERVAL_SECONDS
from ai_client import send_to_soar
from console import print_alert

# AI 분석이 필요 없는 이벤트(노이즈)
IGNORE_RULES = {
    "Suricata: Alert - SOC HTTP Access Detected",
    "Suricata: Alert - SOC SSH Scan Detected",
}

def follow(file):
    """파일 끝에서부터 계속 새로 추가되는 줄만 읽어오는 함수 (tail -f 같은 동작)"""
    file.seek(0, 2)  # 파일 맨 끝으로 이동 (기존 내용은 무시하고, 새로 추가되는 것만 봄)

    while True:
        line = file.readline()

        if not line:
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        yield line


def main():
    print("=" * 60)
    print("           SOAR AI Monitoring Started")
    print("=" * 60)
    print(f"Monitoring : {ALERTS_FILE}")
    print("Waiting for new alerts...\n")

    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        for line in follow(f):
            line = line.strip()
            if not line:
                continue

            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue

            src_ip = (
                log.get("data", {}).get("srcip")
                or log.get("data", {}).get("src_ip")
                or log.get("srcip")
                or log.get("agent", {}).get("ip")
                or "unknown"
            )
            # IPv6는 자동 차단 대상에서 제외
            if ":" in src_ip:
                continue
            rule = log.get("rule", {}).get("description")

            if not rule:
                rule = "Unknown"

            if rule in IGNORE_RULES:
                continue

            full_log = json.dumps(log, ensure_ascii=False)

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
           
            print_alert(current_time, src_ip, rule)
            
            send_to_soar(src_ip, full_log, rule)


if __name__ == "__main__":
    main()
