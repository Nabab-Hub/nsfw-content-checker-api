import base64
import binascii


def decode_base64_image(value: str) -> bytes:
    """
    Decode a base64 encoded image string.

    Supports:
        - Raw base64 string: /9j/4AAQ...
        - Data URI scheme: data:image/jpeg;base64,/9j/4AAQ...
    """
    if not value or not isinstance(value, str):
        raise ValueError("Image string must not be empty")

    if value.startswith("data:") and "," in value:
        value = value.split(",", 1)[1]

    # Remove any surrounding whitespace or newlines
    value = "".join(value.split())

    try:
        return base64.b64decode(
            value,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 image") from exc
