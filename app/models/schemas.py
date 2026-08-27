from typing import Optional, Union
from pydantic import BaseModel, Field


class ImageRequest(BaseModel):
    image: str = Field(
        ...,
        description="Base64 encoded image string (with or without data URI prefix)",
    )
    detection_point: Optional[Union[bool, str]] = Field(
        default=False,
        description="If true, returns bounding rectangle coordinates (top_left, bottom_right, box)",
    )
    detection_points: Optional[Union[bool, str]] = Field(
        default=None,
        description="Alias for detection_point",
    )
    half_nudity: Optional[Union[bool, str]] = Field(
        default="disabled",
        description="Set to 'enabled' or true to allow non-explicit body exposures (male breasts, armpits, belly)",
    )


class Detection(BaseModel):
    label: str = Field(..., description="NSFW class label")
    score: float = Field(..., description="Detection confidence score (0.0 to 1.0)")
    box: Optional[list[int]] = Field(
        default=None,
        description="Raw bounding box as [x, y, width, height]",
    )
    top_left: Optional[list[int]] = Field(
        default=None,
        description="Left-top corner coordinate [x, y]",
    )
    bottom_right: Optional[list[int]] = Field(
        default=None,
        description="Bottom-right corner coordinate [x + width, y + height]",
    )


class SafetyResponse(BaseModel):
    success: bool = Field(..., description="API operation status")
    issafe: bool = Field(..., description="True if no explicit NSFW content detected")
    message: str = Field(..., description="Status or detection summary message")
    detections: list[Detection] = Field(
        default=[],
        description="List of explicit detections found",
    )


class HealthResponse(BaseModel):
    success: bool = True
    status: str = "ok"


class RootResponse(BaseModel):
    success: bool = True
    name: str = "NSFW Checker API"
    version: str = "1.0.0"
    status: str = "online"


class ErrorDetail(BaseModel):
    success: bool = False
    error: str
    message: str
