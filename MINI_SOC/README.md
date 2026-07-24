# Mini SOC — AI / SOAR

Suricata + Wazuh 로그를 받아 공격을 분류하고, 상관분석 후 위험도를 계산해
SOAR(자동 차단/알림)로 넘기는 파이프라인.

## 프로젝트 구조

```
mini_soc/
├── ai/              # 로그 정규화, 분류, 상관분석, 위험도 계산
├── soar/            # IP 차단, 알림
├── sample_logs/     # 테스트용 샘플 로그 (실제 Suricata/Wazuh 없이 실행 가능)
├── main.py          # 실행 진입점
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 1. 로컬(Python)에서 바로 실행

```bash
cd mini_soc
pip install -r requirements.txt
python main.py
```

---

## 2. Git으로 GitHub에 올리기

### 처음 GitHub에 올릴 때 (아직 저장소가 없는 경우)

```bash
cd mini_soc

# 로컬 git 저장소 초기화
git init
git add .
git commit -m "Initial commit: Mini SOC AI/SOAR pipeline"

# GitHub에서 빈 저장소(mini-soc-ai)를 먼저 만든 후, 그 주소를 연결
git branch -M main
git remote add origin https://github.com/<본인계정>/mini-soc-ai.git
git push -u origin main
```

> GitHub에서 저장소를 만들 때 README/gitignore 자동생성 체크는 **끄고** 만드는 걸 추천합니다 (충돌 방지).

### 이미 만든 저장소를 클론해서 이어서 작업할 때

```bash
git clone https://github.com/<본인계정>/mini-soc-ai.git
cd mini-soc-ai
# 코드 수정 후
git add .
git commit -m "AI 분류 로직 개선"
git push
```

### 참고 — `.gitignore`

`__pycache__/`, `.venv/`, `*.log` 등은 이미 `.gitignore`에 등록되어 있어서 git에 안 올라갑니다.

---

## 3. Docker로 실행

### 3-1. 단독 Docker 명령어로

```bash
cd mini_soc

# 이미지 빌드
docker build -t mini-soc-ai .

# 컨테이너 실행 (기본 dry-run 모드)
docker run --rm mini-soc-ai

# 환경변수 바꿔서 실행하고 싶을 때 (예: 임계치 변경)
docker run --rm -e RISK_BLOCK_THRESHOLD=80 mini-soc-ai

# 실제 로그 파일을 컨테이너에 마운트해서 실행 (예: Wazuh Manager 서버에서 실행하는 경우)
docker run --rm \
  -v /var/ossec/logs/alerts/alerts.json:/app/sample_logs/wazuh_alerts.json:ro \
  -v /var/log/suricata/eve.json:/app/sample_logs/suricata_eve.json:ro \
  mini-soc-ai
```

### 3-2. docker-compose로 (더 편함, 설정이 파일로 관리됨)

```bash
cd mini_soc
docker compose up --build
```

- `docker-compose.yml`에서 환경변수(`RISK_BLOCK_THRESHOLD`, `SLACK_WEBHOOK_URL`, `DRY_RUN_BLOCK` 등)를 직접 수정하면 됩니다.
- 실제 배포 시 `DRY_RUN_BLOCK=false`로 바꾸면 진짜 `iptables` 차단이 실행됩니다. **주의해서 켜세요.**
- 컨테이너 종료: `docker compose down`

---

## 4. 환경변수 목록

| 변수명 | 기본값 | 설명 |
|---|---|---|
| `SURICATA_LOG_PATH` | `sample_logs/suricata_eve.json` | Suricata eve.json 경로 |
| `WAZUH_LOG_PATH` | `sample_logs/wazuh_alerts.json` | Wazuh alerts.json 경로 |
| `RISK_BLOCK_THRESHOLD` | `90` | 이 점수 이상이면 자동 차단 |
| `CORRELATION_WINDOW_MIN` | `10` | 같은 IP를 하나의 시나리오로 묶는 시간(분) |
| `SLACK_WEBHOOK_URL` | (없음) | 설정하면 실제 Slack 알림 전송, 없으면 dry-run |
| `DRY_RUN_BLOCK` | `true` | `false`로 하면 실제 iptables 차단 실행 |

---

## 5. Wazuh Manager 서버(Ubuntu2)에 실제 배포할 때 순서

1. 이 저장소를 Ubuntu2에 `git clone`
2. Docker가 없다면 설치: `curl -fsSL https://get.docker.com | sh`
3. `docker-compose.yml`의 volumes를 실제 로그 경로로 수정
   - Wazuh 로그: 보통 `/var/ossec/logs/alerts/alerts.json`
   - Suricata 로그: 보통 `/var/log/suricata/eve.json`
4. `SLACK_WEBHOOK_URL` 설정 (실제 알림 받으려면)
5. `docker compose up -d --build` 로 백그라운드 실행
6. 로그 확인: `docker compose logs -f`
