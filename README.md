# RAKSHA AI

Android scam-protection assistant. Watches permitted Android notifications, investigates suspicious content with a LangGraph-based multi-agent backend, and shows an explainable risk alert before the user acts.

## Project structure

```
raksha-ai/
├── android/     # Android app (notification listener, UI, API client)
├── backend/     # FastAPI backend + LangGraph agent workflow
├── data/        # Local data storage
├── tests/       # Test suite
```

## Status

Notification capture + dashboard UI are implemented for WhatsApp (`com.whatsapp`). Backend calls are **stubbed** — events are logged locally and shown in the app, but nothing is sent to FastAPI yet.

---

## One-time machine setup 

You do **not** need Android Studio. This project builds entirely from the command line.

### 1. Install a JDK

Install **Eclipse Temurin JDK 17**:
- Windows: `winget install EclipseAdoptium.Temurin.17.JDK`
- Mac: `brew install openjdk@17`
- Linux: `sudo apt install temurin-17-jdk` (or use adoptium.net)

Verify: `java -version` should print something with `17` in it.

### 2. Install the Android command-line SDK tools

1. Download **"Command line tools only"** from the official Android developer downloads page (do not download full Android Studio).
2. Unzip it and set up the folder structure Android expects: `cmdline-tools/latest/...`
3. Set environment variables:
   - `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) → path to your SDK folder
   - Add `platform-tools` and `cmdline-tools/latest/bin` to your `PATH`
4. Run:
   ```bash
   sdkmanager --licenses
   sdkmanager "platform-tools" "build-tools;34.0.0" "platforms;android-34"
   ```
5. Verify: `adb version` should print a version number.

### 3. Install Python 3.11+ (for backend work)

Needed once backend work starts. Not required just to build the Android app.

---

## Clone and build the Android app

```bash
git clone <this-repo-url>
cd raksha-ai
```

Gradle dependencies (libraries the code uses) install themselves automatically the first time you build — you don't manually fetch these, similar to how `npm install` reads `package.json`. Just run:

```bash
./gradlew installDebug
```

The first run will download Gradle itself plus all project dependencies (a few hundred MB, one-time). This requires a phone connected below.

## Connect your phone

1. On your phone: Settings → About phone → tap "Build number" 7 times → enables Developer Options.
2. Settings → Developer Options → turn on **USB debugging**.
3. Plug in your phone with a USB-C cable, tap "Allow" on the popup that appears on your phone.
4. Verify: `adb devices` should list your phone.
5. You only need the cable plugged in while installing a build or viewing live logs (`adb logcat`) — unplug it for normal use.

## Grant notification access (manual, per install)

Android requires a human to enable this — it cannot be granted by code:

Settings → Apps → Special app access → Notification access → toggle on **RAKSHA AI**.

## Test notification capture (current milestone)

Backend networking is intentionally stubbed. When a WhatsApp notification arrives, RAKSHA AI:

1. Parses title/text/URLs/attachment-like filenames
2. Logs the `SecurityEvent` with tag `RAKSHA` (view with `adb logcat -s RAKSHA`)
3. Shows the event live in the **Dashboard** list (no HTTP request is made)

### How to test on your phone

1. Install the latest build: `./gradlew installDebug` (or `gradle installDebug` if the wrapper download times out)
2. Open **RAKSHA AI** → tap **Enable notification access** if prompted, then toggle RAKSHA AI on in system settings
3. Return to the Dashboard (keep the app open, or reopen it after granting access)
4. From another phone (or WhatsApp Web), send yourself a WhatsApp message like:
   ```
   Check this link https://example.com/test and download update.apk
   ```
5. Confirm the message appears at the top of the Dashboard with URL count `1` and attachment count `1`
6. Optional: run `adb logcat -s RAKSHA` to see the stub backend log line (`would POST ... not sent`)

## Backend (FastAPI + LangGraph)

The investigation pipeline is a fixed LangGraph graph (not Deep Agents):

`START → planner → (message / url / attachment in parallel) → aggregator → risk_engine → explanation → END`

Gemini (`gemini-3.6-flash`) is used for the message and explanation nodes. Safe Browsing and VirusTotal are **optional**: missing keys log a warning and return `status: unknown` so the graph still runs.

```bash
cp .env.example .env   # set GOOGLE_API_KEY from https://aistudio.google.com
docker compose up --build backend
```

Then `POST /api/events/analyze` with a `SecurityEvent` JSON body. Health check: `GET /health`.

Run the sample investigation test (prints the `RiskReport`):

```bash
docker compose run --rm backend python -m pytest /tests/test_analyze_endpoint.py -s
```

---

## Troubleshooting

- `adb devices` shows nothing → check the USB cable supports data transfer (not power-only), and that you tapped "Allow" on the phone's popup.
- Build fails on `sdkmanager` step → re-run `sdkmanager --licenses` and accept all.
- App installs but notifications aren't detected → confirm notification access was manually granted in phone Settings (see above).
