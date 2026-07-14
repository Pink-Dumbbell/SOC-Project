import json
import time
import requests

ALERTS_FILE = "sample_alerts.json"   # 나중에 실제 Wazuh alerts.json 경로로 교체
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
        print(f"[분석 결과] {result}")
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

            src_ip = log.get("data", {}).get("srcip", "unknown")
            full_log = log.get("full_log", "")

            print(f"\n[새 Alert 발견] src_ip={src_ip}, full_log={full_log}")
            send_to_soar(src_ip, full_log)


if __name__ == "__main__":
    main()