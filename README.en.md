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

**Download & Install**
- Get the latest release: https://github.com/oopsylol/Local2FA/releases
- macOS: download the `.dmg`, mount it, and drag `Local2FA.app` into `Applications`.
- Windows: download the installer and follow the setup.

**Quick Start**
- On first launch, set a master password (for local encryption).
- Add accounts (issuer, secret or import an otpauth URL) and view QR codes.
- Copy 2FA codes when logging in.

**Build from Source (optional)**
- Install deps: `npm install`
- Build frontend: `npm run build`
- Package desktop app (Tauri): `npx tauri build`