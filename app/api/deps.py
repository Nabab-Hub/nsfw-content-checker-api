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

    # --------------------------------------------------------
    # Service Entitlement / Subscription Verification
    # A universal key is valid only for services the user subscribed to.
    # --------------------------------------------------------
    user_id = key_data.get("userId")
    SERVICE_ID = "nsfw-detection"
    is_authorized = False

    if user_id:
        # 1. Check if user is platform admin
        try:
            user_snap = db.collection("users").document(user_id).get()
            if user_snap.exists and (user_snap.to_dict() or {}).get("role") == "admin":
                is_authorized = True
        except Exception:
            pass

        # 2. Check admin override
        if not is_authorized:
            try:
                override_snap = db.collection("userAccessOverrides").document(f"{user_id}_{SERVICE_ID}").get()
                if override_snap.exists:
                    granted = (override_snap.to_dict() or {}).get("granted")
                    if granted is False:
                        # Check if user has an active subscription that supersedes this revocation
                        has_active_sub = False
                        try:
                            now_ms = current_timestamp_ms()
                            subs = (
                                db.collection("subscriptions")
                                .where(filter=firestore.FieldFilter("userId", "==", user_id))
                                .where(filter=firestore.FieldFilter("status", "in", ["active", "pending"]))
                                .stream()
                            )
                            for s in subs:
                                sdata = s.to_dict() or {}
                                if sdata.get("currentPeriodEnd", 0) > now_ms:
                                    sub_svc = sdata.get("serviceId", "")
                                    if sub_svc in [SERVICE_ID, "all"]:
                                        has_active_sub = True
                                        break
                                    plan_id = sdata.get("planId")
                                    if plan_id:
                                        plan_doc = db.collection("plans").document(plan_id).get()
                                        if plan_doc.exists:
                                            allowed = (plan_doc.to_dict() or {}).get("allowedServiceIds", [])
                                            if "*" in allowed or "all" in allowed or SERVICE_ID in allowed:
                                                has_active_sub = True
                                                break
                        except Exception:
                            pass

                        if has_active_sub:
                            is_authorized = True
                            try:
                                override_snap.reference.delete()
                            except Exception:
                                pass
                        else:
                            raise HTTPException(
                                status_code=403,
                                detail={
                                    "success": False,
                                    "error": "service_access_revoked",
                                    "message": f"Access to '{SERVICE_ID}' has been revoked by an administrator.",
                                },
                            )
                    if granted is True:
                        is_authorized = True
            except HTTPException:
                raise
            except Exception:
                pass

        # 3. Check active subscriptions in Firestore
        if not is_authorized:
            try:
                now_ms = current_timestamp_ms()
                subs = (
                    db.collection("subscriptions")
                    .where(filter=firestore.FieldFilter("userId", "==", user_id))
                    .where(filter=firestore.FieldFilter("status", "in", ["active", "pending"]))
                    .stream()
                )
                for s in subs:
                    sdata = s.to_dict() or {}
                    period_end = sdata.get("currentPeriodEnd", 0)
                    if period_end > now_ms:
                        sub_svc = sdata.get("serviceId", "")
                        if sub_svc in [SERVICE_ID, "all"]:
                            is_authorized = True
                            break
                        # Check bundle plan
                        plan_id = sdata.get("planId")
                        if plan_id:
                            plan_doc = db.collection("plans").document(plan_id).get()
                            if plan_doc.exists:
                                allowed_svcs = (plan_doc.to_dict() or {}).get("allowedServiceIds", [])
                                if "*" in allowed_svcs or "all" in allowed_svcs or SERVICE_ID in allowed_svcs:
                                    is_authorized = True
                                    break
            except Exception:
                pass

        if not is_authorized:
            raise HTTPException(
                status_code=403,
                detail={
                    "success": False,
                    "error": "service_not_subscribed",
                    "message": f"Access Denied: Your account does not have an active subscription for '{SERVICE_ID}'. Please subscribe to this service in your CyliumOS dashboard to unlock access.",
                },
            )

    return {
        "key_id": key_doc.id,
        "key_ref": key_ref,
        "key_hash": key_hash,
        "user_id": user_id,
        "plan": key_data.get("plan"),
        "key_prefix": key_data.get("keyPrefix"),
        "created_at": key_data.get("createdAt"),
        "expires_at": expires_at,
        "monthly_limit": monthly_limit,
        "request_count": request_count,
        "status": status,
    }

