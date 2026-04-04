"""
Dummy traffic scheduler.
Sends valid onion-wrapped dummy packets on a randomized schedule.
"""
import asyncio
import random

from secure_tunnel.onion import build_dummy_onion
from secure_tunnel.config import DUMMY_CONFIG


async def run_dummy_sender(ws, route_session_keys: list, config: dict = None):
    """
    Continuously send dummy onion packets at random intervals.
    ws: websockets connection
    route_session_keys: list of session keys for each hop
    """
    cfg = config or DUMMY_CONFIG
    while True:
        await asyncio.sleep(random.uniform(cfg["min_interval"], cfg["max_interval"]))
        if random.random() > cfg["ratio"]:
            continue
        try:
            frame = build_dummy_onion(route_session_keys)
            await ws.send(frame)
        except Exception as e:
            print(f"[dummy] send failed, stopping: {e}")
            break
