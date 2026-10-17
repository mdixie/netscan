# Wi-Fi Inspector for Android

Native Kotlin/Jetpack Compose starter app for Android 8+ on a normal, non-rooted phone. Use only on networks you own or have permission to assess.

## Run

### Alternative: build on GitHub without local Android tools

1. Create a GitHub repository and upload the contents of this project to its root. Include `.github/workflows/build-apk.yml` (it may be hidden by your file browser).
2. Open the repository's **Actions** tab, choose **Build Android APK**, and click **Run workflow**. The workflow also runs on pushes to `main` or `master`.
3. When the build succeeds, open its run and download **WifiInspector-debug-apk** from **Artifacts**. Extract the download to get `app-debug.apk`.
4. Copy the APK to your phone, open it, and allow installation from that source when Android prompts you.

The workflow installs Java, Gradle, and Android SDK tools, runs the included unit tests, and creates a signed debug APK. It does not publish the app or upload it to Google Play. This alternative has been prepared but has not been run from this workspace; it requires a GitHub repository with Actions enabled and successful dependency downloads on GitHub's runner.

### Local Android Studio build

Open this directory in a current Android Studio release, install Android SDK Platform 35, select JDK 17 or newer for Gradle, and sync using Gradle 8.9. Run the `app` configuration on a physical phone connected to Wi-Fi. Android emulators normally expose a virtual network rather than your Wi-Fi LAN.

This project does not yet include the Gradle wrapper. With Gradle 8.9 installed, run `gradle wrapper --gradle-version 8.9` to generate it, then `./gradlew testDebugUnitTest assembleDebug`. The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

## Implemented

- Reads IPv4 address/prefix, default gateway, DNS servers, and interface from Android's connectivity APIs.
- Scans the connected Wi-Fi subnet (/22 through /30) with eight device workers and 350 ms TCP connect timeouts. Larger networks are rejected rather than silently truncated.
- Checks 33 common TCP ports. An accepted connection or explicit connection refusal counts as a response. Silent devices can be missed. No ICMP/raw socket privileges are needed.
- Offers all TCP ports 1–65535 for a discovered device, using 32 concurrent workers.
- Displays open ports, conventional service labels, and potential exposure findings with evidence and remediation advice.
- Supports cancellation and shares a JSON report as text through Android's share sheet. Results stay in memory; no cloud service or analytics is used.

## Limits and next steps

This is an initial implementation, not a complete vulnerability scanner. Service labels come from port numbers, not protocol fingerprints. It does not retrieve banners, inspect TLS certificates, look up CVEs, test credentials, or confirm exploits. Reported findings are configuration review prompts, not confirmed vulnerabilities. A clean result does not prove security.

IPv6 and UDP discovery, mDNS/SSDP names, historical reports, and service/version fingerprinting are not implemented. MAC addresses and reliable vendor identification generally cannot be obtained for other clients by a normal Android app. Router client isolation, firewalls, sleeping devices, and timeouts make inventories incomplete. A router integration would be needed for an authoritative connected-client list.

SSID is not collected, so the app does not request location permissions. It targets Android API 35; future Android targets may require runtime local-network permissions. The UI remains in the foreground during scans; background continuation is not implemented. Cancelled full scans discard partial port results and retain the previous completed device result.

Before distributing, validate on physical devices and representative routers. Verify discovery accuracy, cancellation, network changes, port filtering, and behavior with VPNs and client isolation.
