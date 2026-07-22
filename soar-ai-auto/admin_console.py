"""
관리자용 승인 콘솔
영구 차단 요청이 들어오면 화면에 보여주고, y/n으로 승인/거부를 받는다.
"""

import time
import requests

SOAR_API_URL = "http://127.0.0.1:8000"
CHECK_INTERVAL_SECONDS = 5


def main():
    print("=" * 60)
    print("        영구 차단 승인 콘솔 시작")
    print("=" * 60)
    print("영구 차단 요청을 감시합니다...\n")

    while True:
        try:
            res = requests.get(f"{SOAR_API_URL}/pending-approvals", timeout=5)
            pending = res.json()
        except requests.RequestException as e:
            print(f"[에러] 서버 연결 실패: {e}")
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        for src_ip, info in pending.items():
            print("\n" + "=" * 60)
            print("⚠️  영구 차단 승인 요청")
            print(f"IP        : {src_ip}")
            print(f"공격 유형  : {info['predicted_label']}")
            print(f"요청 시간  : {info['requested_at']}")
            print("=" * 60)

            answer = input(f"{src_ip} 를 영구 차단 하시겠습니까? (y/n): ").strip().lower()

            if answer == "y":
                result = requests.post(f"{SOAR_API_URL}/approve", json={"src_ip": src_ip}).json()
                print(f"[승인 완료] {result}")
            else:
                result = requests.post(f"{SOAR_API_URL}/reject", json={"src_ip": src_ip}).json()
                print(f"[거부 완료] {result}")

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()