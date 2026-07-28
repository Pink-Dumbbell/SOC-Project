"""
Risk Level(LOW/MEDIUM/HIGH/CRITICAL)에 따른 자동 대응 정책.
"""

LEVEL_POLICY = {
    "LOW": {
        "action": "log_only",
    },
    "MEDIUM": {
        "action": "notify_only",
    },
    "HIGH": {
        "action": "temporary",
        "duration": 1800,
    },
    "CRITICAL": {
        "action": "permanent",
    },
}
