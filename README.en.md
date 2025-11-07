# Local2FA

Pulling out the phone for 2FA codes often breaks the desktop flow — so I built a lightweight, local desktop client to view and manage 2FA right on the PC.

**Tech Stack**
- Frontend: Vite, Vanilla JavaScript, minimal CSS
- Desktop packaging: Tauri (Rust)
- QR & TOTP: QRCode, Speakeasy

**Highlights**
- Local-first for macOS/Windows; no cloud dependency.
- Add/manage accounts, generate TOTP codes, view/export QR.
- Master-password encryption (on desktop) and a browser dev mode for easy iteration.