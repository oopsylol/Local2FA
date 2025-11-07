# Local2FA

有时候拿起手机查 2FA 验证码会打断在电脑上的节奏——于是我做了一个纯本地、轻量的桌面端工具，让你在 PC 上直接查看与管理 2FA，不用再掏手机。

**技术栈**
- 前端：Vite、原生 JavaScript、少量 CSS
- 桌面封装：Tauri（Rust）
- 二维码与 TOTP：QRCode、Speakeasy

**特点**
- 本地运行，支持 macOS/Windows；不依赖云端服务。
- 支持添加与管理账号，生成 TOTP 验证码，查看/导出二维码。
- 提供主密码加密（在桌面端）及基础的浏览器开发模式（便于调试）。

**下载与安装**
- 到 Releases 下载最新版本：https://github.com/oopsylol/Local2FA/releases
- macOS：下载 `.dmg`，双击挂载后将 `Local2FA.app` 拖入 `Applications`。
- Windows：下载安装包，按提示安装。

**快速使用**
- 首次启动设置主密码（用于本地加密）。
- 添加账号（填写 issuer、secret 或导入 otpauth URL），可查看二维码。
- 在登录时复制 2FA 验证码使用。

**从源码构建（可选）**
- 安装依赖：`npm install`
- 构建前端：`npm run build`
- 打包桌面应用（Tauri）：`npx tauri build`
