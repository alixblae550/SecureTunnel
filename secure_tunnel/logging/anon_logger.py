"""
Anonymized event logger.
Logs only: timestamp, hop_id, session_id, msg_type, payload_len, direction.
Never logs IPs, usernames, or payload content.
"""
import json
import time
from pathlib import Path

LOG_PATH = Path(__file__).parent.parent.parent / "logs" / "anon.log"


def log_event(hop_id: str, session_id: int, msg_type: int, length: int, direction: str):
    record = {
        "ts": round(time.time(), 3),
        "hop": hop_id,
        "sid": session_id,
        "type": msg_type,
        "len": length,
        "dir": direction,
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
