# Local 2FA Manager

A lightweight, cross‑platform local TOTP (Time‑based One‑Time Password) manager. The frontend uses Vite and plain JavaScript; the desktop app is wrapped with Tauri. You can develop in the browser for quick iteration or package it as a desktop app for macOS/Windows/Linux.

## Features
- Double‑click to copy codes: double‑click the code area to copy it, with bilingual toast messages (Chinese/English).
- Internationalization: supports Chinese and English UI texts; native window title is fixed to `Local 2FA Manager`.
- Desktop integration: powered by Tauri for native window and system capabilities (still runnable in browser dev mode when Tauri is unavailable).
- QR and TOTP support: relies on `qrcode` and `speakeasy` libraries (see code for usage).

## Project Structure
- `app/`: frontend pages and scripts (`index.html`, `app.js`, `style.css`).
- `src-tauri/`: Tauri config and Rust main process entry.
- `vite.config.js`: Vite configuration.
- `package.json`: project dependencies and scripts.
- `totp_cli.py`, `totp_gui.py`, `pywebview_app.py`, `sidecar.py`: Python helpers/experimental files.

## Requirements
- Node.js ≥ 18.
- Rust toolchain and Tauri prerequisites:
  - macOS: Xcode CLT, `rustup`, common Homebrew dependencies.
  - Windows: MS VC++ build tools, `rustup`, WebView2.
  - Linux: GTK, WebKit2, `rustup`, and related build tools.

See Tauri docs for details: https://tauri.app/

## Development
1. Install deps:
   ```bash
   npm install
   ```
2. Browser dev (Vite):
   ```bash
   npm run dev
   # visit http://localhost:5173/
   ```
3. Desktop dev (Tauri):
   ```bash
   npm run tauri:dev
   ```

## Build
- Build static frontend:
  ```bash
  npm run build
  # outputs to dist/
  ```
- Package desktop app (Tauri):
  ```bash
  npx tauri build
  ```

## Usage Tips
- Copy codes: double‑click on a `code` area to copy, toast shows:
  - Chinese: `已复制到剪贴板`
  - English: `Copied to clipboard`
- Language switching: UI offers Chinese/English; the window title stays English for consistency.
- Run modes: when Tauri is not detected, you can still develop in the browser.

## License
- Licensed under `ISC` (see `package.json`).

## Acknowledgements
- Thanks to Vite, Tauri, Speakeasy, QRCode and the open‑source ecosystem.

---
For additional docs (screenshots, data storage strategy, security notes, or a bilingual main README), feel free to request and I will extend it.