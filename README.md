#새로 추가된 코드
#blocked_ips     (set)지금 차단 중인 IP 목록을 기억
#lock    여러 요청이 동시에 들어와도 안전하게 목록을 확인/수정하기 위한 안전장치
#temp_block_ip()    이미 차단 중이면 "already_blocked" 반환하고 끝, 아니면 새로 차단 걸고 10초 후 자동 해제 스레드 시작
#threading.Thread(daemon=True)  10초 기다리는 동안 서버 전체가 멈추지 않게, 백그라운드에서 따로 처리