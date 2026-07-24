# 경량 베이스 이미지 (Debian slim, ~50MB)
FROM python:3.12-slim

WORKDIR /app

# requirements 먼저 복사해서 캐시 활용 (코드만 바뀌면 pip install 다시 안 함)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 나머지 소스 복사
COPY . .

# 실전 배포 시 iptables 실행하려면 root 권한 필요하지만,
# 지금은 dry-run 기본값이라 굳이 root 아니어도 됨. 필요시 아래 주석 해제해서 root로 유지.
# USER root

CMD ["python", "main.py"]
