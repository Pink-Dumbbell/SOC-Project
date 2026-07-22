# 1. 베이스 이미지: 파이썬이 이미 설치되어 있는 기본 상자를 가져옴
FROM python:3.11-slim

# 2. 컨테이너 안에서 작업할 폴더 지정
WORKDIR /app

# 3. requirements.txt 먼저 복사해서 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. 나머지 코드 전체 복사
COPY . .

# 5. 컨테이너가 8000번 포트를 쓴다는 것을 명시
EXPOSE 8000

# 6. 컨테이너 실행되면 이 명령어를 자동 실행
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
