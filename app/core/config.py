import os

# Candidate default paths for Firebase service account credentials
DEFAULT_CREDENTIAL_PATHS = [
    os.getenv("FIREBASE_CREDENTIALS"),
    "cyliumos-firebase-adminsdk.json",
    os.path.join(os.path.dirname(__file__), "..", "..", "cyliumos-firebase-adminsdk.json"),
    os.path.join(os.getcwd(), "cyliumos-firebase-adminsdk.json"),
    os.path.join(os.getcwd(), "ai-models", "nsfw-content-checker-api", "cyliumos-firebase-adminsdk.json"),
    "/etc/secrets/firebase-service-account.json",
    "nude-checker-firebase-adminsdk.json",
    "firebase-service-account.json",
]


def get_firebase_credentials_path() -> str:
    """
    Resolve the Firebase credentials JSON file path.
    Prioritizes FIREBASE_CREDENTIALS environment variable, then fallback paths.
    """
    env_path = os.getenv("FIREBASE_CREDENTIALS")
    if env_path and os.path.exists(env_path):
        return env_path

    for path in DEFAULT_CREDENTIAL_PATHS:
        if path and os.path.exists(path):
            return path

    # If env var was set, return that even if missing so error message is clear
    return env_path or "/etc/secrets/firebase-service-account.json"
