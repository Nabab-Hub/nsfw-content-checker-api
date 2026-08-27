import os
import tempfile
from typing import Optional

from nudenet import NudeDetector

from app.core.constants import (
    EXPLICIT_LABELS,
    STRICT_EXPLICIT_LABELS,
)
from app.models.schemas import Detection

_detector: Optional[NudeDetector] = None


def get_detector() -> NudeDetector:
    """
    Get or initialize the NudeDetector instance.
    """
    global _detector
    if _detector is None:
        _detector = NudeDetector()
    return _detector


def analyze_image_nsfw(
    image_bytes: bytes,
    half_nudity_enabled: bool = False,
    include_detection_points: bool = False,
) -> tuple[bool, str, list[Detection]]:
    """
    Analyze image bytes with NudeNet detector and return safety status,
    summary message, and explicit detections.

    :param image_bytes: Raw decoded image bytes
    :param half_nudity_enabled: If True, ignores male breast, armpits, and belly
    :param include_detection_points: If True, populates bounding coordinates
    :return: Tuple of (is_safe: bool, message: str, detections: list[Detection])
    """
    active_explicit_labels = (
        STRICT_EXPLICIT_LABELS if half_nudity_enabled else EXPLICIT_LABELS
    )

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".jpg",
            delete=False,
        ) as temp_file:
            temp_file.write(image_bytes)
            temp_path = temp_file.name

        detector = get_detector()
        results = detector.detect(temp_path)

        explicit_detections: list[Detection] = []

        for item in results:
            label = item.get("class")
            score = float(item.get("score", 0.0))

            if label in active_explicit_labels:
                if (
                    include_detection_points
                    and "box" in item
                    and isinstance(item["box"], (list, tuple))
                    and len(item["box"]) >= 4
                ):
                    raw_box = [int(v) for v in item["box"][:4]]
                    x, y, w, h = raw_box[0], raw_box[1], raw_box[2], raw_box[3]
                    top_left = [x, y]
                    bottom_right = [x + w, y + h]

                    explicit_detections.append(
                        Detection(
                            label=label,
                            score=score,
                            box=raw_box,
                            top_left=top_left,
                            bottom_right=bottom_right,
                        )
                    )
                else:
                    explicit_detections.append(
                        Detection(
                            label=label,
                            score=score,
                        )
                    )

        explicit_detections.sort(
            key=lambda d: d.score,
            reverse=True,
        )

        if explicit_detections:
            highest = explicit_detections[0]
            return (
                False,
                f"NSFW content detected: {highest.label}",
                explicit_detections,
            )

        return (
            True,
            "No explicit content detected",
            [],
        )

    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass
