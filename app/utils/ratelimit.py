import time
from functools import wraps
from flask import request, session, abort


def _client_ip() -> str:
    # Best-effort IP detection (works behind proxies if configured)
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "").strip()
        or request.remote_addr
        or "unknown"
    )


def rate_limit(limit: int = 10, window_seconds: int = 60, key_prefix: str = "rl"):
    """
    Simple session+IP based rate limiter (no dependencies).
    Stores counters in Flask session.

    limit: max requests within window_seconds
    window_seconds: time window
    key_prefix: namespace for this route/feature
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            now = int(time.time())
            window = now // window_seconds

            # user identifier: logged-in user id if present, else anon_id from session, else IP
            user_key = session.get("anon_id") or _client_ip()

            endpoint = request.endpoint or "unknown"
            key = f"{key_prefix}:{endpoint}:{user_key}:{window}"

            bucket = session.get("_ratelimit", {})
            count = int(bucket.get(key, 0)) + 1
            bucket[key] = count

            # cleanup older keys (best effort)
            if len(bucket) > 200:
                # keep only keys from current window (cheap cleanup)
                bucket = {k: v for k, v in bucket.items() if k.endswith(f":{window}")}

            session["_ratelimit"] = bucket

            if count > limit:
                # 429 Too Many Requests
                abort(429)

            return fn(*args, **kwargs)
        return wrapper
    return decorator
