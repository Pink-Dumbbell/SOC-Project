import json
import time
import requests

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"   
SOAR_API_URL = "http://127.0.0.1:8000/analyze"

CHECK_INTERVAL_SECONDS = 3   # 몇 초마다 새 줄이 있는지 확인할지


def follow(file):
    """파일 끝에서부터 계속 새로 추가되는 줄만 읽어오는 함수 (tail -f 같은 동작)"""
    file.seek(0, 2)  # 파일 맨 끝으로 이동 (기존 내용은 무시하고, 새로 추가되는 것만 봄)

    while True:
        line = file.readline()
        if not line:
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue
        yield line


def send_to_soar(src_ip: str, full_log: str):
    """SOAR 서버(/analyze)에 로그를 전송하고 결과를 받는다"""
    payload = {"src_ip": src_ip, "full_log": full_log}

    try:
        response = requests.post(SOAR_API_URL, json=payload, timeout=5)
        result = response.json()
        print("[AI 분석 결과]")
        print(f"공격 유형 : {result['predicted_attack']}")
        print(f"대응 결과 : {result['action']}")
        print("=" * 60)
    except requests.exceptions.RequestException as e:
        print(f"[에러] SOAR 서버 요청 실패: {e}")


def main():
    print(f"'{ALERTS_FILE}' 감시를 시작합니다... (새 Alert가 생기면 자동 분석)")

    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        for line in follow(f):
            line = line.strip()
            if not line:
                continue

            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue

            src_ip = log.get("data", {}).get("src_ip", "unknown")
            # IPv6는 자동 차단 대상에서 제외
            if ":" in src_ip:
                continue
            rule = log.get("rule", {}).get("description", "Unknown")
            full_log = json.dumps(log, ensure_ascii=False)

            print("\n" + "=" * 60)
            print("[새 Alert 수신]")
            print(f"공격 IP : {src_ip}")
            print(f"Rule    : {rule}")
            print("=" * 60)

            send_to_soar(src_ip, full_log)


if __name__ == "__main__":
    main()
