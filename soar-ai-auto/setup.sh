#!/bin/bash

echo "=========================================="
echo "      SOAR AI Environment Checker"
echo "=========================================="
echo

# Python 확인
echo "[1] Python 확인"
if command -v python3 >/dev/null 2>&1; then
    python3 --version
else
    echo "❌ Python3가 설치되어 있지 않습니다."
    exit 1
fi

echo

# Docker 확인
echo "[2] Docker 확인"
if command -v docker >/dev/null 2>&1; then
    docker --version
else
    echo "❌ Docker가 설치되어 있지 않습니다."
    exit 1
fi

echo

# Docker Compose 확인
echo "[3] Docker Compose 확인"
if docker compose version >/dev/null 2>&1; then
    docker compose version
else
    echo "❌ Docker Compose를 사용할 수 없습니다."
fi

echo

# 설정 파일 확인
echo "[4] config.py 확인"
if [ -f config.py ]; then
    echo "✅ config.py 존재"
else
    echo "❌ config.py가 없습니다."
fi

echo

# alerts.json 확인
echo "[5] alerts.json 확인"

ALERT_PATH=$(python3 - <<EOF
from config import ALERTS_FILE
print(ALERTS_FILE)
EOF
)

echo "설정된 경로:"
echo "$ALERT_PATH"
echo

if sudo test -f "$ALERT_PATH"; then
    echo "✅ alerts.json 존재"
    sudo ls -l "$ALERT_PATH"
else
    echo "❌ alerts.json을 찾을 수 없습니다."
fi

# 읽기 권한 확인

echo
echo "[6] alerts.json 읽기 권한 확인"

if [ -r "$ALERT_PATH" ]; then
    echo "✅ 현재 사용자로 읽을 수 있습니다."
else
    echo "⚠️ 현재 사용자는 읽을 수 없습니다."
    echo "watch_alerts.py를 sudo로 실행하거나 권한 설정이 필요합니다."
fi

echo
echo "=========================================="
echo "환경 점검 완료"
echo "=========================================="
