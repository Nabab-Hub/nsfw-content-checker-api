# NSFW Content Checker API

A high-performance automated NSFW content and nudity detection REST API built with **FastAPI**, **NudeNet** (ONNX engine), and **Firebase Firestore** for API key authentication, quota tracking, and usage logging.

---

## Table of Contents

- [Architecture & Directory Structure](#architecture--directory-structure)
- [Prerequisites & Setup](#prerequisites--setup)
  - [Firebase Configuration](#firebase-configuration)
  - [Running with Docker (Recommended)](#running-with-docker-recommended)
  - [Running Locally](#running-locally)
- [Authentication](#authentication)
- [API Endpoints Reference](#api-endpoints-reference)
  - [1. Health Check (`GET /health`)](#1-health-check-get-health)
  - [2. Service Info (`GET /`)](#2-service-info-get-)
  - [3. NSFW Detection (`POST /is_safe`)](#3-nsfw-detection-post-is_safe)
- [Request Parameters](#request-parameters)
- [Feature Details](#feature-details)
  - [Half-Nudity Filtering (`half_nudity`)](#half-nudity-filtering-half_nudity)
  - [Bounding Box Coordinates (`detection_point`)](#bounding-box-coordinates-detection_point)
- [Usage Examples](#usage-examples)
  - [cURL](#curl)
  - [JavaScript / TypeScript (Fetch API)](#javascript--typescript-fetch-api)
  - [Python (requests)](#python-requests)
- [Error Codes & Troubleshooting](#error-codes--troubleshooting)

---

## Architecture & Directory Structure

The application follows a clean, modular architecture separating concerns across routes, services, schemas, and utilities:

```
nsfw-content-checker-api/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application entry point & router mounting
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py              # API key verification & rate-limiting dependency
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── health.py        # /health and / endpoints
│   │       └── nsfw.py          # /is_safe detection endpoint
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py            # Environment configuration & credential path resolution
│   │   └── constants.py         # Detection labels & explicit classes definition
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py           # Pydantic request & response models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── detector.py          # NudeNet detector instance & bounding box calculations
│   │   └── firebase.py          # Firestore connection, quota increment & usage logging
│   └── utils/
│       ├── __init__.py
│       ├── helpers.py           # Boolean parsers, key hashing, timestamps
│       └── image.py             # Base64 image decoding
├── docker-compose.yml           # Docker Compose configuration
├── Dockerfile                   # Production Dockerfile with OpenCV dependencies
├── requirements.txt             # Python dependencies
└── README.md                    # Documentation
```

---

## Prerequisites & Setup

### Firebase Configuration

The API requires a Firebase Service Account JSON file for API key authentication and request quota tracking in Cloud Firestore.

Set the environment variable `FIREBASE_CREDENTIALS` to the path of your service account key file:

```bash
# Linux / macOS / Docker
export FIREBASE_CREDENTIALS="/path/to/firebase-service-account.json"

# Windows PowerShell
$env:FIREBASE_CREDENTIALS = "C:\path\to\firebase-service-account.json"
```

If not specified, the application will automatically look for:
1. `/etc/secrets/firebase-service-account.json`
2. `nude-checker-firebase-adminsdk.json` in the root directory
3. `firebase-service-account.json` in the root directory

#### Firestore Database Schema

The API reads from the `apiKeys` collection and writes to the `usageLogs` collection:

- **`apiKeys` collection document fields:**
  - `keyHash` *(string, required)*: SHA-256 hash of the raw API key
  - `status` *(string, required)*: `'active'` | `'revoked'` | `'expired'`
  - `userId` *(string, optional)*: User/tenant identifier
  - `plan` *(string, optional)*: User subscription tier (e.g. `'pro'`, `'free'`)
  - `monthlyLimit` *(number, optional)*: Maximum requests allowed per month (0 or omitted for unlimited)
  - `requestCount` *(number, optional)*: Number of requests made
  - `expiresAt` *(timestamp/number, optional)*: Expiration timestamp in Unix milliseconds

- **`usageLogs` collection document fields:**
  - `userId` *(string)*
  - `keyId` *(string)*
  - `timestamp` *(number, Unix ms)*
  - `endpoint` *(string, e.g. `"/is_safe"`)*
  - `statusCode` *(number, e.g. `200`)*

---

### Running with Docker (Recommended)

Build and run using Docker Compose:

```bash
docker compose up --build
```

Or build and run manually:

```bash
docker build -t nsfw-checker-api .
docker run -p 8080:8080 -v /path/to/firebase-key.json:/etc/secrets/firebase-service-account.json nsfw-checker-api
```

The API will be available at `http://localhost:8080`.

---

### Running Locally

1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux / macOS:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the development server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
   ```

4. Open API documentation in your browser:
   - Interactive Swagger UI: `http://localhost:8080/docs`
   - ReDoc: `http://localhost:8080/redoc`

---

## Authentication

All detection requests to `/is_safe` require an API key passed via the **`X-API-Key`** HTTP header:

```http
X-API-Key: nsk_live_xxxxxxxxxxxxxxxxxxxxxxxx
```

---

## API Endpoints Reference

### 1. Health Check (`GET /health`)

Check service health and uptime status.

**Response (`200 OK`):**
```json
{
  "success": true,
  "status": "ok"
}
```

---

### 2. Service Info (`GET /`)

Get basic service metadata.

**Response (`200 OK`):**
```json
{
  "success": true,
  "name": "NSFW Checker API",
  "version": "1.0.0",
  "status": "online"
}
```

---

### 3. NSFW Detection (`POST /is_safe`)

Analyze a base64 encoded image for explicit NSFW content.

**Request Headers:**
| Header | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | `string` | **Yes** | Must be `application/json` |
| `X-API-Key` | `string` | **Yes** | Valid customer API key |

---

## Request Parameters

The JSON body for `POST /is_safe` accepts the following fields:

| Field | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `image` | `string` | **Yes** | - | Base64-encoded image string. Supports raw base64 or Data URI format (`data:image/jpeg;base64,...`). |
| `half_nudity` | `string` \| `bool` | No | `"disabled"` | When set to `"enabled"` or `true`, ignores non-explicit exposure (`MALE_BREAST_EXPOSED`, `ARMPITS_EXPOSED`, `BELLY_EXPOSED`). |
| `detection_point` | `bool` \| `string` | No | `false` | When set to `true`, includes bounding rectangle coordinates (`top_left`, `bottom_right`, `box`) in the detections list. |
| `detection_points` | `bool` \| `string` | No | `null` | Alias for `detection_point`. |

---

## Feature Details

### Half-Nudity Filtering (`half_nudity`)

The detector categorizes detections into strict explicit labels and partial exposure labels:

- **Strict Explicit Labels (Always flagged):**
  - `FEMALE_BREAST_EXPOSED`
  - `FEMALE_GENITALIA_EXPOSED`
  - `MALE_GENITALIA_EXPOSED`
  - `BUTTOCKS_EXPOSED`
  - `ANUS_EXPOSED`

- **Half-Nudity Labels:**
  - `MALE_BREAST_EXPOSED`
  - `ARMPITS_EXPOSED`
  - `BELLY_EXPOSED`

#### Behavior:

1. **`half_nudity: "enabled"` (or `true`):**
   - If an image contains **only** `MALE_BREAST_EXPOSED`, `ARMPITS_EXPOSED`, or `BELLY_EXPOSED`, the API considers the image **safe**:
     ```json
     {
       "success": true,
       "issafe": true,
       "message": "No explicit content detected",
       "detections": []
     }
     ```
   - If the image also contains strict explicit content (e.g. `FEMALE_BREAST_EXPOSED`), only the strict violation is returned and `issafe` is `false`.

2. **`half_nudity: "disabled"` (or `false` / omitted):**
   - Any exposed area in the image (including belly or armpits) will be flagged as NSFW:
     ```json
     {
       "success": true,
       "issafe": false,
       "message": "NSFW content detected: BELLY_EXPOSED",
       "detections": [
         {
           "label": "BELLY_EXPOSED",
           "score": 0.88
         }
       ]
     }
     ```

---

### Bounding Box Coordinates (`detection_point`)

Control whether coordinate rectangles for detections are returned in the response:

1. **`detection_point: false` (Default):**
   - Compact payload returning only `label` and `score`:
     ```json
     {
       "label": "FEMALE_BREAST_EXPOSED",
       "score": 0.94
     }
     ```

2. **`detection_point: true`:**
   - Detailed payload with top-left corner and bottom-right corner pixel coordinates:
     ```json
     {
       "label": "FEMALE_BREAST_EXPOSED",
       "score": 0.94,
       "box": [120, 85, 210, 160],
       "top_left": [120, 85],
       "bottom_right": [330, 245]
     }
     ```
     - `top_left`: `[x, y]` (left top corner)
     - `bottom_right`: `[x + width, y + height]` (right bottom corner)
     - `box`: `[x, y, width, height]`

---

## Usage Examples

### cURL

#### 1. Standard Check (Default options)
```bash
curl -X POST "http://localhost:8080/is_safe" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: nsk_live_xxxxxxxxxxxxxxxxxxxxxxxx" \
  -d '{
    "image": "/9j/4AAQSkZJRgABAQEASABIAAD..."
  }'
```

#### 2. Half-Nudity Enabled with Detection Coordinates
```bash
curl -X POST "http://localhost:8080/is_safe" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: nsk_live_xxxxxxxxxxxxxxxxxxxxxxxx" \
  -d '{
    "image": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD...",
    "half_nudity": "enabled",
    "detection_point": true
  }'
```

---

### JavaScript / TypeScript (Fetch API)

```typescript
async function checkImageSafety(base64Image: string, apiKey: string) {
  const response = await fetch("http://localhost:8080/is_safe", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
    },
    body: JSON.stringify({
      image: base64Image,
      half_nudity: "enabled",     // Allow armpits/belly/male breast
      detection_point: true,       // Return [top_left, bottom_right] points
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    console.error(`Error (${response.status}):`, data.detail);
    return;
  }

  if (data.issafe) {
    console.log("Image is clean!");
  } else {
    console.warn("NSFW Detected:", data.message);
    data.detections.forEach((d) => {
      console.log(`- ${d.label} (${(d.score * 100).toFixed(1)}%) at`, d.top_left, "to", d.bottom_right);
    });
  }
}
```

---

### Python (requests)

```python
import base64
import requests

API_URL = "http://localhost:8080/is_safe"
API_KEY = "nsk_live_xxxxxxxxxxxxxxxxxxxxxxxx"

# Convert local image file to base64
with open("sample.jpg", "rb") as f:
    base64_image = base64.b64encode(f.read()).decode("utf-8")

payload = {
    "image": base64_image,
    "half_nudity": "enabled",
    "detection_point": True,
}

headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
}

response = requests.post(API_URL, json=payload, headers=headers)

if response.status_code == 200:
    result = response.json()
    print("Is Safe:", result["issafe"])
    print("Message:", result["message"])
    for det in result.get("detections", []):
        print(f"- {det['label']}: Score {det['score']:.2f}")
        if "top_left" in det:
            print(f"  Box: Top-Left {det['top_left']}, Bottom-Right {det['bottom_right']}")
else:
    print(f"Error {response.status_code}:", response.json())
```

---

## Error Codes & Troubleshooting

When an error occurs, the API returns a standard HTTP status code and a descriptive JSON body inside the `detail` object:

### Error Summary Table

| HTTP Status | Error Code (`error`) | Description |
| :--- | :--- | :--- |
| **`400 Bad Request`** | `empty_image` | Image string is empty or missing content. |
| **`400 Bad Request`** | `invalid_image` | Base64 string is malformed or invalid. |
| **`401 Unauthorized`** | `missing_api_key` | `X-API-Key` header was not supplied in the request. |
| **`401 Unauthorized`** | `invalid_api_key` | Provided API key does not exist or has an invalid signature. |
| **`403 Forbidden`** | `api_key_inactive` | API key status is set to `'revoked'` or is not active. |
| **`403 Forbidden`** | `api_key_expired` | API key has passed its `expiresAt` timestamp. |
| **`429 Too Many Requests`** | `monthly_limit_reached` | User's `requestCount` has reached or exceeded `monthlyLimit`. |
| **`500 Internal Error`** | `internal_error` | Server error occurred while decoding or processing image with NudeNet. |

---

### Error Response Examples

#### 1. Missing API Key (`401 Unauthorized`)
```json
{
  "detail": {
    "success": false,
    "error": "missing_api_key",
    "message": "X-API-Key header is required"
  }
}
```

#### 2. Invalid API Key (`401 Unauthorized`)
```json
{
  "detail": {
    "success": false,
    "error": "invalid_api_key",
    "message": "Invalid API key"
  }
}
```

#### 3. Inactive or Revoked Key (`403 Forbidden`)
```json
{
  "detail": {
    "success": false,
    "error": "api_key_inactive",
    "message": "API key is not active (status: revoked)"
  }
}
```

#### 4. Expired API Key (`403 Forbidden`)
```json
{
  "detail": {
    "success": false,
    "error": "api_key_expired",
    "message": "API key has expired"
  }
}
```

#### 5. Monthly Limit Reached (`429 Too Many Requests`)
```json
{
  "detail": {
    "success": false,
    "error": "monthly_limit_reached",
    "message": "Monthly API request limit reached"
  }
}
```

#### 6. Invalid Base64 Image (`400 Bad Request`)
```json
{
  "detail": {
    "success": false,
    "error": "invalid_image",
    "message": "Invalid base64 image"
  }
}
```