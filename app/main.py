import base64
import binascii
import hashlib
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional

import firebase_admin
from firebase_admin import credentials, firestore

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import APIKeyHeader

from pydantic import BaseModel

from nudenet import NudeDetector


# ============================================================
# Firebase
# ============================================================

FIREBASE_CREDENTIALS = os.getenv(
    "FIREBASE_CREDENTIALS",
    "/etc/secrets/nude-checker-firebase-adminsdk.json",
)

if not os.path.exists(FIREBASE_CREDENTIALS):
    raise RuntimeError(
        f"Firebase credentials not found: {FIREBASE_CREDENTIALS}"
    )


# if not firebase_admin._apps:
cred = credentials.Certificate(
    FIREBASE_CREDENTIALS
)

firebase_admin.initialize_app(cred)


db = firestore.client()


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title="NSFW Checker API",
    version="1.0.0",
)


# ============================================================
# NudeNet
# ============================================================

# Load NudeNet only once when the API starts.
detector = NudeDetector()


# ============================================================
# API Key
# ============================================================

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


# ============================================================
# Explicit labels
# ============================================================

EXPLICIT_LABELS = {
    "BUTTOCKS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_BREAST_EXPOSED",
    "ANUS_EXPOSED",
    "ARMPITS_EXPOSED",
    "BELLY_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
}


# ============================================================
# Request / Response models
# ============================================================

class ImageRequest(BaseModel):
    image: str


class Detection(BaseModel):
    label: str
    score: float


class SafetyResponse(BaseModel):
    success: bool
    issafe: bool
    message: str
    detections: list[Detection] = []


# ============================================================
# Helpers
# ============================================================

def hash_api_key(api_key: str) -> str:
    """
    Convert the customer's raw API key into SHA-256.

    Example:

        nsk_live_xxxxxxxxx

    becomes:

        8cd2c46e0ea3827...
    """

    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def current_timestamp_ms() -> int:
    """
    Current UTC time as Unix milliseconds.
    """

    return int(
        datetime.now(timezone.utc).timestamp() * 1000
    )


def decode_base64_image(value: str) -> bytes:
    """
    Decode a base64 image.

    Supports:

        /9j/4AAQ...

    and:

        data:image/jpeg;base64,/9j/4AAQ...
    """

    if value.startswith("data:") and "," in value:
        value = value.split(",", 1)[1]

    value = "".join(value.split())

    try:
        return base64.b64decode(
            value,
            validate=True,
        )

    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            "Invalid base64 image"
        ) from exc


# ============================================================
# API Key Authentication
# ============================================================

def verify_api_key(
    api_key: Optional[str] = Depends(api_key_header),
):
    """
    Validate the API key against:

        apiKeys/{keyHash}

    Firestore schema:

        keyHash
        keyPrefix
        userId
        plan
        createdAt
        expiresAt
        monthlyLimit
        requestCount
        status
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

    key_hash = hash_api_key(api_key)

    # --------------------------------------------------------
    # Direct Firestore document lookup
    #
    # Recommended structure:
    #
    # apiKeys/{keyHash}
    #
    # If your current document ID is different, see the note
    # below the code.
    # --------------------------------------------------------

    key_ref = (
        db.collection("apiKeys")
        .document(key_hash)
    )

    key_snapshot = key_ref.get()

    if not key_snapshot.exists:
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "error": "invalid_api_key",
                "message": "Invalid API key",
            },
        )

    key_data = key_snapshot.to_dict()

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    status = key_data.get("status")

    if status != "active":
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": "api_key_inactive",
                "message": "API key is not active",
            },
        )

    # --------------------------------------------------------
    # Expiration
    #
    # Your expiresAt is Unix milliseconds.
    #
    # Example:
    #
    # 1790310193165
    # --------------------------------------------------------

    expires_at = key_data.get("expiresAt")

    if expires_at is None:
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": "invalid_api_key",
                "message": "API key has no expiration date",
            },
        )

    try:
        expires_at = int(expires_at)

    except (TypeError, ValueError):
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "error": "invalid_api_key_configuration",
                "message": "Invalid API key expiration",
            },
        )

    now_ms = current_timestamp_ms()

    if expires_at <= now_ms:
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": "api_key_expired",
                "message": "API key has expired",
            },
        )

    # --------------------------------------------------------
    # Monthly usage
    # --------------------------------------------------------

    request_count = int(
        key_data.get("requestCount", 0)
    )

    monthly_limit = int(
        key_data.get("monthlyLimit", 0)
    )

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
    # Return authenticated API-key information
    # --------------------------------------------------------

    return {
        "key_hash": key_hash,
        "key_ref": key_ref,
        "user_id": key_data.get("userId"),
        "plan": key_data.get("plan"),
        "key_prefix": key_data.get("keyPrefix"),
        "created_at": key_data.get("createdAt"),
        "expires_at": expires_at,
        "monthly_limit": monthly_limit,
        "request_count": request_count,
        "status": status,
    }


# ============================================================
# Usage counter
# ============================================================

@firestore.transactional
def increment_usage_transaction(
    transaction,
    key_ref,
):
    """
    Atomically increment requestCount.

    This prevents:

        request A reads 100
        request B reads 100
        request A writes 101
        request B writes 101

    which would incorrectly count 2 requests as 1.
    """

    snapshot = key_ref.get(
        transaction=transaction
    )

    if not snapshot.exists:
        raise RuntimeError(
            "API key disappeared during request"
        )

    data = snapshot.to_dict()

    current_count = int(
        data.get("requestCount", 0)
    )

    monthly_limit = int(
        data.get("monthlyLimit", 0)
    )

    # Check the limit AGAIN inside the transaction.
    #
    # This is important because another request could have
    # consumed the final available request between the
    # initial authentication check and this transaction.
    if (
        monthly_limit > 0
        and current_count >= monthly_limit
    ):
        raise RuntimeError(
            "MONTHLY_LIMIT_REACHED"
        )

    transaction.update(
        key_ref,
        {
            "requestCount": current_count + 1,
        },
    )


def increment_usage(key_ref):
    """
    Execute the Firestore transaction.
    """

    transaction = db.transaction()

    try:
        increment_usage_transaction(
            transaction,
            key_ref,
        )

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


# ============================================================
# Health endpoint
# ============================================================

@app.get("/health")
def health():
    return {
        "success": True,
        "status": "ok",
    }


# ============================================================
# API information
# ============================================================

@app.get("/")
def root():
    return {
        "success": True,
        "name": "NSFW Checker API",
        "version": "1.0.0",
        "status": "online",
    }


# ============================================================
# /is_safe
# ============================================================

@app.post(
    "/is_safe",
    response_model=SafetyResponse,
)
def is_safe(
    request: ImageRequest,
    api_key=Depends(verify_api_key),
):
    """
    Main NSFW detection endpoint.

    Authentication happens before this function runs.
    """

    # --------------------------------------------------------
    # Decode image
    # --------------------------------------------------------

    try:
        image_bytes = decode_base64_image(
            request.image
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "error": "invalid_image",
                "message": str(exc),
            },
        )

    if not image_bytes:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "error": "empty_image",
                "message": "Image is empty",
            },
        )

    # --------------------------------------------------------
    # NudeNet expects an image path.
    #
    # Write the decoded image to a temporary file.
    # --------------------------------------------------------

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            suffix=".jpg",
            delete=False,
        ) as temp_file:

            temp_file.write(image_bytes)

            temp_path = temp_file.name

        # ----------------------------------------------------
        # Run NudeNet
        # ----------------------------------------------------

        results = detector.detect(
            temp_path,
        )

        # ----------------------------------------------------
        # Extract explicit detections
        # ----------------------------------------------------

        explicit_detections = []

        for detection in results:

            label = detection.get("class")

            score = float(
                detection.get("score", 0)
            )

            if label in EXPLICIT_LABELS:

                explicit_detections.append(
                    Detection(
                        label=label,
                        score=score,
                    )
                )

        # ----------------------------------------------------
        # Count the request
        #
        # Only count successfully processed requests.
        # ----------------------------------------------------

        increment_usage(
            api_key["key_ref"]
        )

        # ----------------------------------------------------
        # Sort detections
        # ----------------------------------------------------

        explicit_detections.sort(
            key=lambda item: item.score,
            reverse=True,
        )

        # ----------------------------------------------------
        # Unsafe
        # ----------------------------------------------------

        if explicit_detections:

            highest = explicit_detections[0]

            return SafetyResponse(
                success=True,
                issafe=False,
                message=(
                    "NSFW content detected: "
                    f"{highest.label}"
                ),
                detections=explicit_detections,
            )

        # ----------------------------------------------------
        # Safe
        # ----------------------------------------------------

        return SafetyResponse(
            success=True,
            issafe=True,
            message="No explicit content detected",
            detections=[],
        )

    except HTTPException:
        raise

    except Exception as exc:

        print(
            f"NudeNet processing error: {exc}"
        )

        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "error": "internal_error",
                "message": "Failed to process image",
            },
        )

    finally:

        # ----------------------------------------------------
        # Delete temporary image
        # ----------------------------------------------------

        if temp_path:

            try:
                os.remove(temp_path)

            except OSError:
                pass
