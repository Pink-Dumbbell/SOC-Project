new_alert = '{"rule":{"id":"31108","description":"Web Application Attack SQL Injection"},"agent":{"name":"rocky"},"data":{"srcip":"10.20.20.200"},"full_log":"GET /DVWA?id=99 UNION SELECT username,password FROM users--"}'

with open("sample_alerts.json", "a", encoding="utf-8") as f:
    f.write(new_alert + "\n")

print("새 alert 추가 완료!")