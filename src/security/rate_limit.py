"""Per-session sliding-window rate limiting.

Streamlit keeps one `session_state` per browser session/tab, which is the
natural (and only meaningful, given this app has no shared backend process
serving multiple concurrent HTTP clients behind a load balancer) unit to rate
limit against here. This bounds both cost (OpenAI calls) and abuse.
"""
import time
from collections import deque

import streamlit as st


def check_rate_limit(action: str, max_calls: int, window_seconds: int) -> bool:
    """Return True if this call is allowed under the limit, False if the
    caller should be blocked. Records the attempt regardless of outcome so
    repeated hits keep being counted within the window."""
    key = f"_rate_{action}"
    now = time.time()
    timestamps: deque = st.session_state.setdefault(key, deque())
    while timestamps and now - timestamps[0] > window_seconds:
        timestamps.popleft()
    if len(timestamps) >= max_calls:
        return False
    timestamps.append(now)
    return True
