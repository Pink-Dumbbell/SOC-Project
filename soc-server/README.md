# Deploy Wazuh Docker in single node configuration

# SOC Server

## 소개

SOC Server는 Wazuh Manager를 중심으로 이벤트를 수집하고 분석하는 서버

 프로젝트에서는 다음 기능을 담당.

- Wazuh Manager
- Wazuh Dashboard
- Wazuh Indexer
- SpiderFoot(OSINT)

1차 디렉토리

## Directory

```
soc-server
│
├── automation
├── config
├── docker-compose.yml
├── generate-indexer-certs.yml
├── spiderfoot
└── systemd

## Components

### Wazuh Manager

- Agent 이벤트 수집
- Suricata 로그 분석
- Alert 생성

### Wazuh Dashboard

- 실시간 이벤트 확인
- Agent 상태 확인
- Alert 모니터링

### SpiderFoot

## 실행

Wazuh

```bash
cd /home/soc/SOC-Project/soc-server/
docker compose up -d
```

SpiderFoot

```bash
cd /home/soc/SOC-Project/soc-server/spiderfoot
cd spiderfoot
docker compose up -d

desktop icon


cp desktop/*.desktop ~/Desktop/
chmod +x ~/Desktop/*.desktop

gio set ~/Desktop/wazuh.desktop metadata::trusted true
gio set ~/Desktop/spiderfoot.desktop metadata::trusted true


-------------------------------------------------------------------


차단 아이콘 만들기 

chmod +x /home/soc/SOC-Project/soc-server/desktop/soar-admin.desktop

cp /home/soc/SOC-Project/soc-server/desktop/soar-admin.desktop /home/soc/Desktop/

chmod +x /home/soc/Desktop/soar-admin.desktop
