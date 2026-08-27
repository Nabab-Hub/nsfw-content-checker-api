from typing import Optional
from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from firebase_admin import firestore

from app.services.firebase import get_firestore_client
from app.utils.helpers import current_timestamp_ms, hash_api_key

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def verify_api_key(
    api_key: Optional[str] = Depends(api_key_header),
) -> dict:
    """
    Validate the API key against Firestore collection `apiKeys`.

    Firestore schema:
        keyHash (string) - SHA-256 hash of raw API key
        keyPrefix (string)
        userId (string)
        plan (string)
        createdAt (number/timestamp)
        expiresAt (number/timestamp or null)
        monthlyLimit (number)
        requestCount (number)
        status (string: 'active' | 'revoked' | 'expired')
    """
    # --------------------------------------------------------
    # Missing key
    # --------------------------------------------------------
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "error": "missing_api_key",
                "message": "X-API-Key header is required",
            },
        )

    # --------------------------------------------------------
    # Hash supplied key
    # --------------------------------------------------------
    key_hash = hash_api_key(api_key.strip())
    db = get_firestore_client()

    # --------------------------------------------------------
    # Firestore lookup:
    # 1. Query `apiKeys` where `keyHash == key_hash`
    # 2. Fallback to direct document lookup if doc ID is key_hash
    # --------------------------------------------------------
    query = (
        db.collection("apiKeys")
        .where(filter=firestore.FieldFilter("keyHash", "==", key_hash))
        .limit(1)
        .stream()
    )
    docs = list(query)

    if docs:
        key_doc = docs[0]
        key_ref = key_doc.reference
        key_data = key_doc.to_dict() or {}
    else:
        # Fallback: check if doc ID is key_hash
        fallback_ref = db.collection("apiKeys").document(key_hash)
        fallback_snap = fallback_ref.get()
        if not fallback_snap.exists:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "error": "invalid_api_key",
                    "message": "Invalid API key",
                },
            )
        key_doc = fallback_snap
        key_ref = fallback_ref
        key_data = fallback_snap.to_dict() or {}

    # --------------------------------------------------------
    # Status validation
    # --------------------------------------------------------
    status = key_data.get("status", "active")
    if status != "active":
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": "api_key_inactive",
                "message": f"API key is not active (status: {status})",
            },
        )

    # --------------------------------------------------------
    # Expiration (Unix milliseconds)
    # --------------------------------------------------------
    expires_at = key_data.get("expiresAt")
    if expires_at is not None:
        try:
            if hasattr(expires_at, "timestamp"):
                expires_at_ms = int(expires_at.timestamp() * 1000)
            elif isinstance(expires_at, (int, float)):
                expires_at_ms = int(expires_at)
            elif isinstance(expires_at, str) and expires_at.isdigit():
                expires_at_ms = int(expires_at)
            else:
                expires_at_ms = None

            now_ms = current_timestamp_ms()
            if expires_at_ms is not None and expires_at_ms <= now_ms:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "success": False,
                        "error": "api_key_expired",
                        "message": "API key has expired",
                    },
                )
        except HTTPException:
            raise
        except Exception:
            pass

    # --------------------------------------------------------
    # Monthly usage limit
    # --------------------------------------------------------
    request_count = int(key_data.get("requestCount", 0))
    monthly_limit = int(key_data.get("monthlyLimit", 0))

    if monthly_limit > 0 and request_count >= monthly_limit:
        raise HTTPException(
            status_code=429,
            detail={
                "success": False,
                "error": "monthly_limit_reached",
                "message": "Monthly API request limit reached",
            },
        )

    return {
        "key_id": key_doc.id,
        "key_ref": key_ref,
        "key_hash": key_hash,
        "user_id": key_data.get("userId"),
        "plan": key_data.get("plan"),
        "key_prefix": key_data.get("keyPrefix"),
        "created_at": key_data.get("createdAt"),
        "expires_at": expires_at,
        "monthly_limit": monthly_limit,
        "request_count": request_count,
        "status": status,
    }
