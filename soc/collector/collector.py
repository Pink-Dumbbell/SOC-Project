import time
import json
import os

LOG_FILE = "/logs/eve.json"

def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(1)
            continue
        yield line

while not os.path.exists(LOG_FILE):
    print("[wait] eve.json 생성 대기 중...")
    time.sleep(2)

print("[START] Suricata 로그 수집 시작")

with open(LOG_FILE, "r") as f:
    for line in follow(f):
        try:
            event = json.loads(line)

            if event.get("event_type") == "alert":
                print("[ALERT]")
                print("시간:", event.get("timestamp"))
                print("공격IP:", event.get("src_ip"))
                print("목적지IP:", event.get("dest_ip"))
                print("룰:", event.get("alert", {}).get("signature"))
                print("-" * 40)

        except Exception as e:
            print("로그 파싱 오류:", e)
