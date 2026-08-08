# RAKSHA AI

Android scam-protection assistant with a Python backend for threat analysis.

## Project structure

- `android/` — Android app (notification listener, UI, API client)
- `backend/` — FastAPI backend with LangGraph workflow
- `data/` — Local data storage
- `tests/` — Test suite

## Prerequisites

- JDK 17+
- Android SDK (platform-tools, build-tools 34, android-34)
- Python 3.11+ (for backend, later)

## Build & install (Android)

```bash
./gradlew installDebug
```

## Setup

1. Copy `.env.example` to `.env` and fill in API keys.
2. Enable USB debugging on your Android device.
3. Run `adb devices` to confirm connection.

## Status

Scaffold only — no feature logic implemented yet.
