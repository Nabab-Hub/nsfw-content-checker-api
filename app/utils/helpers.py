import hashlib
from datetime import datetime, timezone
from typing import Optional, Union


def hash_api_key(api_key: str) -> str:
    """
    Convert raw API key into SHA-256 hex string for database lookup.

    Example:
        cyk_live_xxxxxxxxx -> 8cd2c46e0ea3827...
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def current_timestamp_ms() -> int:
    """
    Current UTC time as Unix milliseconds.
    """
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def is_half_nudity_enabled(val: Optional[Union[bool, str]]) -> bool:
    """
    Check if half_nudity mode is enabled.

    When enabled, MALE_BREAST_EXPOSED, ARMPITS_EXPOSED, and BELLY_EXPOSED
    are tolerated and not flagged as NSFW violations.
    """
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ("enabled", "enable", "true", "1", "yes", "on")
    return False


def is_detection_point_enabled(
    detection_point: Optional[Union[bool, str]],
    detection_points: Optional[Union[bool, str]] = None,
) -> bool:
    """
    Check if bounding box coordinate points should be returned in response detections.
    """
    val = detection_point if detection_point is not None else detection_points
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes", "on", "enabled", "enable")
    return False
