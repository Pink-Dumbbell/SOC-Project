import requests
from config import SOAR_API_URL
from console import print_ai_result


def send_to_soar(src_ip: str, full_log: str):
    payload = {"src_ip": src_ip, "full_log": full_log}

    try:
        response = requests.post(SOAR_API_URL, json=payload, timeout=5)
        response.raise_for_status()

        result = response.json()

        print_ai_result(result)

    except requests.exceptions.RequestException as e:
        print(f"[에러] SOAR 서버 요청 실패: {e}")
