"""
SOAR Logger

AI 분석 및 자동 대응 결과를 로그 파일에 기록한다.
"""

from datetime import datetime
from pathlib import Path

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "actions.log"


def log_action(
    src_ip: str,
    attack: str,
    risk: str,
    playbook: str,
    action: str,
):
    """
    SOAR 대응 결과를 로그 파일에 저장한다.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f"Time       : {timestamp}\n")
        f.write(f"Source IP  : {src_ip}\n")
        f.write(f"Attack     : {attack}\n")
        f.write(f"Risk       : {risk}\n")
        f.write(f"Playbook   : {playbook}\n")
        f.write(f"Action     : {action}\n")
        f.write("=" * 60 + "\n\n")

def get_logs(limit: int = 20):
    """
    최근 대응 로그를 반환한다.
    """

    if not LOG_FILE.exists():
        return ""

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    return "".join(lines[-limit * 8:])    
