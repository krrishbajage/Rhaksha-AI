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

Scaffold only — no feature logic implemented yet. Empty app currently builds and installs on a physical device.

---

## One-time machine setup (every teammate does this once)

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

## Backend setup (once backend work starts)

```bash
cd backend
cp .env.example .env   # fill in API keys
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## Troubleshooting

- `adb devices` shows nothing → check the USB cable supports data transfer (not power-only), and that you tapped "Allow" on the phone's popup.
- Build fails on `sdkmanager` step → re-run `sdkmanager --licenses` and accept all.
- App installs but notifications aren't detected → confirm notification access was manually granted in phone Settings (see above).