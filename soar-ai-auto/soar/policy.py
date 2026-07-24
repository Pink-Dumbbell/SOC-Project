POLICY = {
    "sql_injection": {
        "action": "permanent",
    },
    "xss": {
        "action": "temporary",
        "duration": 1800,
    },
    "directory_traversal": {
        "action": "temporary",
        "duration": 1800,
    },
    "command_injection": {
        "action": "permanent",
    },
    "brute_force": {
        "action": "temporary",
        "duration": 600,
    },
}
