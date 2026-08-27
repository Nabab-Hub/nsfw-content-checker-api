from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import verify_api_key
from app.models.schemas import ImageRequest, SafetyResponse
from app.services.detector import analyze_image_nsfw
from app.services.firebase import increment_usage, log_usage
from app.utils.helpers import is_detection_point_enabled, is_half_nudity_enabled
from app.utils.image import decode_base64_image

router = APIRouter(tags=["NSFW Detection"])


@router.post(
    "/is_safe",
    response_model=SafetyResponse,
    response_model_exclude_none=True,
    summary="Detect explicit NSFW content in an image",
)
def is_safe(
    request: ImageRequest,
    api_key: dict = Depends(verify_api_key),
):
    """
    Analyze a base64 encoded image for NSFW and explicit content.

    ### Headers:
    - **X-API-Key**: Valid API key generated from dashboard.

    ### Options:
    - **half_nudity**: When set to `'enabled'` or `true`, non-explicit exposed body parts
      (`MALE_BREAST_EXPOSED`, `ARMPITS_EXPOSED`, `BELLY_EXPOSED`) are considered safe.
    - **detection_point**: When set to `true`, detection bounding rectangle coordinates
      (`top_left`, `bottom_right`, `box`) are returned.
    """
    # --------------------------------------------------------
    # Decode base64 image
    # --------------------------------------------------------
    try:
        image_bytes = decode_base64_image(request.image)
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
    # Process image with detector
    # --------------------------------------------------------
    try:
        half_nudity_active = is_half_nudity_enabled(request.half_nudity)
        include_points = is_detection_point_enabled(
            request.detection_point,
            request.detection_points,
        )

        is_image_safe, message, detections = analyze_image_nsfw(
            image_bytes=image_bytes,
            half_nudity_enabled=half_nudity_active,
            include_detection_points=include_points,
        )

        # ----------------------------------------------------
        # Count the request & log usage
        # ----------------------------------------------------
        increment_usage(api_key["key_ref"])

        log_usage(
            user_id=api_key.get("user_id"),
            key_id=api_key.get("key_id"),
            endpoint="/is_safe",
            status_code=200,
        )

        return SafetyResponse(
            success=True,
            issafe=is_image_safe,
            message=message,
            detections=detections,
        )

    except HTTPException:
        raise
    except Exception as exc:
        print(f"NudeNet processing error: {exc}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "error": "internal_error",
                "message": "Failed to process image",
            },
        )
