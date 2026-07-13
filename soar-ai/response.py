def generate_block_command(src_ip: str) -> str:
    """공격 IP를 차단하는 iptables 명령어를 만든다"""
    return f"iptables -A INPUT -s {src_ip} -j DROP"


def should_block(predicted_label: str) -> bool:
    """이 공격 유형이 자동 차단 대상인지 판단"""
    blockable_attacks = {
        "sql_injection",
        "xss",
        "directory_traversal",
        "command_injection",
        "brute_force",
    }
    return predicted_label in blockable_attacks

    import paramiko

# Ubuntu1 Gateway 서버 접속 정보
GATEWAY_HOST = "10.10."       # Ubuntu1 Gateway의 실제 IP로 나중에 교체
GATEWAY_PORT = 22
GATEWAY_USERNAME = "soc"         # 실제 로그인 계정으로 교체
GATEWAY_PASSWORD = "qhdks12"  # 또는 SSH 키 방식 사용 권장


def generate_block_command(src_ip: str) -> str:
    """공격 IP를 차단하는 iptables 명령어를 만든다"""
    return f"iptables -A INPUT -s {src_ip} -j DROP"


def should_block(predicted_label: str) -> bool:
    """이 공격 유형이 자동 차단 대상인지 판단"""
    blockable_attacks = {
        "sql_injection",
        "xss",
        "directory_traversal",
        "command_injection",
        "brute_force",
    }
    return predicted_label in blockable_attacks


def execute_block_on_gateway(command: str) -> dict:
    """Ubuntu1 Gateway에 SSH로 접속해서 실제로 iptables 명령을 실행한다"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            hostname=GATEWAY_HOST,
            port=GATEWAY_PORT,
            username=GATEWAY_USERNAME,
            password=GATEWAY_PASSWORD,
            timeout=5,
        )

        # sudo 권한이 필요한 경우 대비 (비밀번호를 표준입력으로 넘김)
        stdin, stdout, stderr = client.exec_command(f"sudo -S {command}")
        stdin.write(GATEWAY_PASSWORD + "\n")
        stdin.flush()

        error_output = stderr.read().decode().strip()
        client.close()

        if error_output and "password" not in error_output.lower():
            return {"success": False, "message": error_output}

        return {"success": True, "message": "차단 명령 실행 완료"}

    except Exception as e:
        return {"success": False, "message": str(e)}