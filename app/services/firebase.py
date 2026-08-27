import os
from typing import Optional
import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import HTTPException

from app.core.config import get_firebase_credentials_path
from app.utils.helpers import current_timestamp_ms

_db: Optional[firestore.Client] = None


def get_firestore_client() -> firestore.Client:
    """
    Get or initialize the Firestore client singleton.
    """
    global _db

    if _db is not None:
        return _db

    cred_path = get_firebase_credentials_path()

    if not os.path.exists(cred_path):
        raise RuntimeError(
            f"Firebase credentials not found at '{cred_path}'. "
            "Please ensure FIREBASE_CREDENTIALS points to a valid JSON file."
        )

    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)

    _db = firestore.client()
    return _db


@firestore.transactional
def _increment_usage_transaction(transaction, key_ref):
    """
    Atomically increment requestCount inside a Firestore transaction.
    """
    snapshot = key_ref.get(transaction=transaction)

    if not snapshot.exists:
        raise RuntimeError("API key disappeared during request")

    data = snapshot.to_dict() or {}
    current_count = int(data.get("requestCount", 0))
    monthly_limit = int(data.get("monthlyLimit", 0))

    if monthly_limit > 0 and current_count >= monthly_limit:
        raise RuntimeError("MONTHLY_LIMIT_REACHED")

    transaction.update(
        key_ref,
        {
            "requestCount": current_count + 1,
        },
    )


def increment_usage(key_ref) -> None:
    """
    Execute the Firestore transaction to increment request count.
    """
    db = get_firestore_client()
    transaction = db.transaction()
    try:
        _increment_usage_transaction(transaction, key_ref)
    except RuntimeError as exc:
        if str(exc) == "MONTHLY_LIMIT_REACHED":
            raise HTTPException(
                status_code=429,
                detail={
                    "success": False,
                    "error": "monthly_limit_reached",
                    "message": "Monthly API request limit reached",
                },
            )
        raise


def log_usage(
    user_id: Optional[str],
    key_id: Optional[str],
    endpoint: str = "/is_safe",
    status_code: int = 200,
) -> None:
    """
    Log usage entry to `usageLogs` collection matching the dashboard schema.
    """
    try:
        db = get_firestore_client()
        db.collection("usageLogs").add(
            {
                "userId": user_id or "",
                "keyId": key_id or "",
                "timestamp": current_timestamp_ms(),
                "endpoint": endpoint,
                "statusCode": status_code,
            }
        )
    except Exception as exc:
        print(f"Failed to write usage log: {exc}")
