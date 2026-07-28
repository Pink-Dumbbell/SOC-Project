#영구 차단 위험도를 가진 공격이 들어올 시 관리자 승인받는 구조 수정

공격 탐지 → policy.py에서 "permanent"면
   ↓
blocker.py: 즉시 차단 안 하고 "승인 대기 목록"에만 등록
   ↓
[새 파일] admin_console.py: 주기적으로 대기 목록 확인 → 관리자한테 y/n 물어봄
   ↓
y → main.py의 /approve 호출 → 그제서야 진짜 SSH 차단 실행
n → /reject 호출 → 아무 일도 안 일어남