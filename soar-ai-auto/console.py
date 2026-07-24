def print_alert(current_time, src_ip, rule):
    print("\n" + "=" * 60)
    print("                 SOAR AI SOC Console")
    print("=" * 60)
    print("[새 Alert 수신]\n")

    print(f"Time      : {current_time}")
    print(f"Source IP : {src_ip}")
    print(f"Rule      : {rule}")

    print("=" * 60)


def print_ai_result(result):
    print("\n[AI Analysis]\n")

    print(f"Attack    : {result['predicted_attack']}")
    print(f"Risk      : {result['risk']}")
    print(f"Playbook  : {result['playbook']}")

    incident = result.get("incident")
    if incident and incident.get("is_multi_stage"):
        print("\n[상관분석 결과]")
        print(f"Incident ID   : {incident['incident_id']}")
        print(f"Attack Flow   : {' -> '.join(incident['attack_flow'])}")
        print(f"Stage         : {incident['stage']}")
        print(f"Incident Risk : {incident['risk_score']}/100")

    print("\nPlaybook")
    print("-" * 40)

    for idx, step in enumerate(result["steps"], start=1):
        print(f"  {idx}. {step}")

    print("\nRecommendation")
    print("-" * 40)
    print(result["recommendation"])

    print("\nAction")
    print("-" * 40)
    print(result["action"])

    print("=" * 60)