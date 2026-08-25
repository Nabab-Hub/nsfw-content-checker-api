import base64
import binascii
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel
from nudenet import NudeDetector


app = FastAPI(
    title="NudeNet Safety API",
    version="1.0.0",
)

# Load once when the container starts.
# Do NOT create NudeDetector() for every request.
detector = NudeDetector()


# These are the labels that should make an image unsafe.
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


def decode_base64_image(value: str) -> bytes:
    """
    Supports both:

        /9j/4AAQ...
    
    and:

        data:image/jpeg;base64,/9j/4AAQ...
    """

    if "," in value and value.startswith("data:"):
        value = value.split(",", 1)[1]

    # Remove accidental whitespace/newlines.
    value = "".join(value.split())

    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 image") from exc


@app.get("/health")
def health():
    return {
        "success": True,
        "status": "ok",
    }


@app.post("/is_safe", response_model=SafetyResponse)
def is_safe(request: ImageRequest):
    try:
        image_bytes = decode_base64_image(request.image)

        if not image_bytes:
            return SafetyResponse(
                success=False,
                issafe=False,
                message="Image is empty",
            )

        # NudeNet accepts bytes directly.
        results = detector.detect(image_bytes)

        explicit_detections = []

        for detection in results:
            label = detection.get("class")
            score = float(detection.get("score", 0))

            if label in EXPLICIT_LABELS:
                explicit_detections.append(
                    Detection(
                        label=label,
                        score=score,
                    )
                )

        if explicit_detections:
            # Pick the highest-confidence explicit detection.
            explicit_detections.sort(
                key=lambda x: x.score,
                reverse=True,
            )

            highest = explicit_detections[0]

            return SafetyResponse(
                success=True,
                issafe=False,
                message=(
                    f"NSFW content detected: "
                    f"{highest.label} "
                    f"(confidence: {highest.score:.2f})"
                ),
                detections=explicit_detections,
            )

        return SafetyResponse(
            success=True,
            issafe=True,
            message="No explicit content detected",
            detections=[],
        )

    except ValueError as exc:
        return SafetyResponse(
            success=False,
            issafe=False,
            message=str(exc),
        )

    except Exception as exc:
        # Don't expose internal exception details to clients.
        print(f"Detection error: {exc}")

        return SafetyResponse(
            success=False,
            issafe=False,
            message="Failed to process image",
        )
