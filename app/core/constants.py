# ============================================================
# Explicit detection labels configuration
# ============================================================

HALF_NUDITY_LABELS = {
    "MALE_BREAST_EXPOSED",
    "ARMPITS_EXPOSED",
    "BELLY_EXPOSED",
}

STRICT_EXPLICIT_LABELS = {
    "BUTTOCKS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "FEMALE_GENITALIA_EXPOSED",
    "ANUS_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
}

EXPLICIT_LABELS = STRICT_EXPLICIT_LABELS | HALF_NUDITY_LABELS
