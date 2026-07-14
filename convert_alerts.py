import json
import csv

INPUT_FILE = "sample_alerts.json"   # 나중에 실제 alerts.json으로 교체
OUTPUT_FILE = "dataset.csv"

# rule.description에 어떤 단어가 들어있으면 어떤 라벨로 매핑할지 정하는 규칙
LABEL_KEYWORDS = {
    "sql injection": "sql_injection",
    "xss": "xss",
    "cross site": "xss",
    "directory traversal": "directory_traversal",
    "path traversal": "directory_traversal",
    "command injection": "command_injection",
    "brute force": "brute_force",
    "failed login": "brute_force",

    # Windows Server 공격 관련
    "rdp": "rdp_brute_force",
    "remote desktop": "rdp_brute_force",
    "smb": "smb_exploit",
    "eternalblue": "smb_exploit",
    "windows logon": "windows_brute_force",
}


def map_description_to_label(description: str):
    """rule.description 문장을 보고 우리 라벨로 변환"""
    description_lower = description.lower()
    for keyword, label in LABEL_KEYWORDS.items():
        if keyword in description_lower:
            return label
    return None  # 어떤 키워드에도 안 걸리면 학습에서 제외


def convert(input_file: str, output_file: str):
    rows = []

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue  # 빈 줄 건너뜀

            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue  # 형식이 깨진 줄은 건너뜀

            description = log.get("rule", {}).get("description", "")
            full_log = log.get("full_log", "")

            label = map_description_to_label(description)

            if label is None:
                continue  # 우리가 학습할 공격 유형이 아니면 제외

            rows.append({"full_log": full_log, "label": label})

    # CSV로 저장
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["full_log", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"변환 완료! {len(rows)}개 행을 {output_file}에 저장했습니다.")


if __name__ == "__main__":
    convert(INPUT_FILE, OUTPUT_FILE)