# Local 2FA Manager（本地双重验证管理器）

一个轻量、跨平台的本地 2FA（基于时间的一次性密码，TOTP）管理器。前端使用 Vite 与原生 JavaScript，桌面端封装采用 Tauri。可在浏览器开发模式下快速迭代，也可以打包为桌面应用在 macOS/Windows/Linux 上运行。

## 主要特性
- 双击复制验证码：在验证码区域双击即可复制，并显示多语言提示（中文/英文）。
- 桌面集成：通过 Tauri 桌面环境提供原生窗口与系统能力（开发模式下也可在浏览器中运行）。
- 二维码与 TOTP 支持：依赖 `qrcode` 与 `speakeasy` 等库（具体用法见代码）。

## 目录结构
- `app/`：前端页面与脚本（`index.html`、`app.js`、`style.css`）。
- `src-tauri/`：Tauri 桌面应用配置与 Rust 主进程入口。
- `vite.config.js`：Vite 配置。
- `package.json`：项目依赖与脚本。
（已移除 Python 辅助/实验性文件，当前项目不依赖 Python。）

## 环境与依赖
- Node.js ≥ 18（用于前端开发与构建）。
- Rust 工具链与 Tauri 依赖（桌面端运行/打包）：
  - macOS：Xcode Command Line Tools、`rustup`、Homebrew 常用依赖。
  - Windows：Microsoft VC++、`rustup`、WebView2。
  - Linux：GTK、WebKit2、`rustup`、相关构建工具。

更多细节请参考 Tauri 官方文档：https://tauri.app/

## 开发与运行
1. 安装依赖：
   ```bash
   npm install
   ```
2. 浏览器开发模式（Vite）：
   ```bash
   npm run dev
   # 默认访问 http://localhost:5173/
   ```
3. 桌面开发模式（Tauri）：
   ```bash
   npm run tauri:dev
   ```

## 构建
- 构建静态前端：
  ```bash
  npm run build
  # 产物输出到 dist/（如需静态部署）
  ```
- 打包桌面应用（Tauri）：
  ```bash
  npx tauri build
  ```

## 使用提示
- 复制验证码：在验证码 `code` 区域双击，即会复制到剪贴板，并显示提示：
  - 中文：`已复制到剪贴板`
  - 英文：`Copied to clipboard`
- 语言切换：页面提供语言选择（中文/英文）；为了统一体验，窗口标题保持英文。
- 运行模式：若未检测到 Tauri 环境，项目仍可在浏览器中运行以便调试与开发。

## 许可证
- 本项目采用 `ISC` 许可证（见 `package.json`）。

## 致谢
- Vite、Tauri、Speakeasy、QRCode 等开源生态。
