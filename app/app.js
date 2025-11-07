// 纯前端 2FA 管理器
// 功能：
// - 添加/编辑/删除账号（issuer/label/secret/digits/period）
// - 计算并显示 TOTP，带倒计时
// - 导入/导出为 JSON 文件
// - 可选自动使用 localStorage 持久化

const STORAGE_KEY = 'local-2fa-accounts-v1';
const CONFIG_KEY = 'local-2fa-config-v1';
// 浏览器预览模式：用于标记已完成一次模拟“主密码设置”，避免反复提示
const PREVIEW_SETUP_DONE_KEY = 'local-2fa-preview-setup-done';
// 浏览器预览模式：保存主密码的 SHA-256（仅用于预览解锁校验）
const PREVIEW_MASTER_HASH_KEY = 'local-2fa-preview-master-sha256';
// Python/pywebview 与 sidecar 已移除，保持为 null 以避免误用
const bridge = null;
const tauriProcess = null;
// Tauri 原生命令调用（v1/v2 兼容：core.invoke 或 tauri.invoke）
const tauriInvoke = (() => {
  const t = window.__TAURI__;
  if (!t) return null;
  // v1 旧版：顶层 __TAURI__.invoke
  if (typeof t.invoke === 'function') return t.invoke;
  if (t.core && typeof t.core.invoke === 'function') return t.core.invoke;
  if (t.tauri && typeof t.tauri.invoke === 'function') return t.tauri.invoke;
  return null;
})();
// 惰性获取 Tauri 调用器：适配延迟注入与 v1/v2 差异
function getTauriInvoke() {
  if (tauriInvoke) return tauriInvoke;
  const t = window.__TAURI__;
  if (!t) return null;
  if (typeof t.invoke === 'function') return t.invoke;
  if (t.core && typeof t.core.invoke === 'function') return t.core.invoke;
  if (t.tauri && typeof t.tauri.invoke === 'function') return t.tauri.invoke;
  return null;
}

// 轮询等待 Tauri 注入，提升在 dev 模式（remote devUrl）下的健壮性
async function waitForTauriInvoke(timeoutMs = 5000) {
  const start = Date.now();
  let inv = getTauriInvoke();
  if (inv) return inv;
  while (Date.now() - start < timeoutMs) {
    await new Promise(r => setTimeout(r, 50));
    inv = getTauriInvoke();
    if (inv) return inv;
  }
  return null;
}

// 更新调试面板中的环境徽章（Tauri: ON/OFF）
function updateEnvBadge() {
  try {
    const el = document.getElementById('envBadge');
    if (!el) return;
    const on = !!getTauriInvoke();
    el.textContent = on ? 'Tauri: ON' : 'Tauri: OFF';
    el.classList.remove('env-on', 'env-off');
    el.classList.add(on ? 'env-on' : 'env-off');
  } catch (_) { /* ignore */ }
}

// 应用构建标记（用于确认当前打开的是最新构建）
function applyBuildMarker() {
  try {
    const el = document.getElementById('buildMarker');
    if (!el) return;
    // 固定文本标记 + 运行环境提示
    const env = getTauriInvoke() ? 'Desktop' : 'Browser';
    el.textContent = `BUILD-1106 • ${env}`;
  } catch (_) { /* ignore */ }
}

async function generateQrViaTauri(url) {
  const inv = getTauriInvoke();
  if (!inv) return null;
  try {
    const res = await inv('generate_qr', { url });
    if (res && typeof res === 'object' && res.data) {
      return { mime: res.mime || 'image/svg+xml', data: res.data };
    }
    if (typeof res === 'string') {
      const s = res.trim();
      if (s.startsWith('data:')) {
        const m = s.match(/^data:([^;]+);base64,(.+)$/);
        if (m) return { mime: m[1], data: m[2] };
      }
      if (s.startsWith('<svg')) {
        const b64 = btoa(unescape(encodeURIComponent(s)));
        return { mime: 'image/svg+xml', data: b64 };
      }
      if (/^[A-Za-z0-9+/=]+$/.test(s)) {
        return { mime: 'image/svg+xml', data: s };
      }
      try {
        const obj = JSON.parse(s);
        if (obj && obj.data) return { mime: obj.mime || 'image/svg+xml', data: obj.data };
      } catch (_) { /* ignore */ }
    }
    return null;
  } catch (e) {
    console.debug('Tauri generate_qr 调用失败', e);
    return null;
  }
}

function generateQrInBrowser(url) {
  try {
    // 1) 优先使用 CDN 提供的 qrcode-generator（全局函数 qrcode）
    if (typeof window.qrcode === 'function') {
      // 使用自动版本（0）根据数据长度选择尺寸，避免空白 QR
      const qr = window.qrcode(0, 'L');
      qr.addData(url);
      qr.make();
      let svg = qr.createSvgTag(4, 2); // 单元大小与边距
      // 取主题强调色，直接写入 SVG，背景透明
      const accent = (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#85b6ff').trim();
      svg = svg.replace(/fill="black"/g, `fill="${accent}"`)
               .replace(/fill="white"/g, 'fill="none"');
      const b64 = btoa(unescape(encodeURIComponent(svg)));
      return { mime: 'image/svg+xml', data: b64 };
    }
    // 2) 兼容旧的 window.qrcodeGenerator 命名
    if (window.qrcodeGenerator && typeof window.qrcodeGenerator.qrcode === 'function') {
      const qr = window.qrcodeGenerator.qrcode(0, 'L');
      qr.addData(url);
      qr.make();
      let svg = qr.createSvgTag(4, 2);
      const accent = (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#85b6ff').trim();
      svg = svg.replace(/fill="black"/g, `fill="${accent}"`)
               .replace(/fill="white"/g, 'fill="none"');
      const b64 = btoa(unescape(encodeURIComponent(svg)));
      return { mime: 'image/svg+xml', data: b64 };
    }
    return null;
  } catch (_) {
    return null;
  }
}

// Sidecar 支持已移除：直接返回失败码以禁用相关路径
async function execSidecar(args, { stdin } = {}) { return { code: -1 }; }

/** Base32 解码（RFC 4648，不含 padding 可兼容） */
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = '';
  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned[i]);
    if (val === -1) throw new Error('Base32 字符不合法');
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

/** Hex(MD5) 或 Base32 解码自动识别 */
function decodeSecret(input) {
  const s = (input || '').trim();
  // 仅包含十六进制字符则按 hex 解析（常见 16 或 32 长度）
  if (/^[0-9a-fA-F]+$/.test(s)) {
    if (s.length % 2 !== 0) throw new Error('Hex 密钥长度需为偶数');
    const bytes = new Uint8Array(s.length / 2);
    for (let i = 0; i < s.length; i += 2) {
      bytes[i / 2] = parseInt(s.slice(i, i + 2), 16);
    }
    return bytes;
  }
  // 否则尝试 Base32
  return base32Decode(s);
}

/** 将数字计数器转为 8 字节大端 */
function counterToBytes(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // 写入高位到低位（大端）
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  return new Uint8Array(buf);
}

/** 使用 Web Crypto 计算 HMAC-SHA1 */
async function hmacDigest(algorithm, keyBytes, msgBytes) {
  const algoMap = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
  const hashName = algoMap[(algorithm || 'SHA1').toUpperCase()] || 'SHA-1';
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: { name: hashName } }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

// 预览模式：计算字符串的 SHA-256 十六进制表示
async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 计算 TOTP */
async function totp({ secretBase32, period = 30, digits = 6, algorithm = 'SHA1', timestamp = Date.now() }) {
  const key = decodeSecret(secretBase32);
  const counter = Math.floor(timestamp / 1000 / period);
  const msg = counterToBytes(counter);
  const hmac = await hmacDigest(algorithm, key, msg);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
               ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) |
               (hmac[offset + 3] & 0xff);
  const otp = (code % 10 ** digits).toString().padStart(digits, '0');
  const remaining = period - Math.floor((timestamp / 1000) % period);
  return { otp, remaining };
}

// 状态管理
let state = {
  accounts: [],
  editingIndex: null,
  fileHandle: null,
  boundPath: null,
  config: { accent: '#85b6ff', language: 'en' },
};

// 最近一次持久化错误信息（便于在删除/保存失败时显示调试信息）
let lastError = null;

// DOM 引用
const accountsContainer = document.getElementById('accountsContainer');
const addAccountBtn = document.getElementById('addAccountBtn');
const newFileBtn = document.getElementById('newFileBtn');
const bindFileBtn = document.getElementById('bindFileBtn');
const fileStatusEl = document.getElementById('fileStatus');

const accountDialog = document.getElementById('accountDialog');
const accountForm = document.getElementById('accountForm');
const dialogTitle = document.getElementById('dialogTitle');
const deleteAccountBtn = document.getElementById('deleteAccountBtn');
const deleteConfirmBar = document.getElementById('deleteConfirmBar');
const deleteConfirmText = document.getElementById('deleteConfirmText');
const confirmYesBtn = document.getElementById('confirmYesBtn');
const confirmNoBtn = document.getElementById('confirmNoBtn');
const labelInput = document.getElementById('labelInput');
const issuerInput = document.getElementById('issuerInput');
const secretInput = document.getElementById('secretInput');
const digitsInput = document.getElementById('digitsInput');
const periodInput = document.getElementById('periodInput');
const algorithmInput = document.getElementById('algorithmInput');
const importOtpauthBtn = document.getElementById('importOtpauthBtn');
const langSelect = document.getElementById('langSelect');
const langSelectUI = document.getElementById('langSelectUI');
const resetBtn = document.getElementById('resetBtn');
// 主密码相关 DOM
const enableMasterBtn = document.getElementById('enableMasterBtn');
const masterDialog = document.getElementById('masterDialog');
const masterForm = document.getElementById('masterForm');
const masterTitle = document.getElementById('masterTitle');
const masterPwdInput = document.getElementById('masterPwdInput');
const masterConfirmRow = document.getElementById('masterConfirmRow');
const masterConfirmInput = document.getElementById('masterConfirmInput');
const masterHint = document.getElementById('masterHint');
const masterSubmitBtn = document.getElementById('masterSubmitBtn');
// 锁屏遮罩 DOM
const setupOverlay = document.getElementById('setupOverlay');
const setupTitle = document.getElementById('setupTitle');
const setupHint = document.getElementById('setupHint');
// 备用设置主密码表单（遮罩内，当 <dialog> 不可用时启用）
const setupPwdRow = document.getElementById('setupPwdRow');
const setupPwdInput = document.getElementById('setupPwdInput');
const setupConfirmRow = document.getElementById('setupConfirmRow');
const setupConfirmInput = document.getElementById('setupConfirmInput');
const setupPwdLabel = document.getElementById('setupPwdLabel');
const setupConfirmLabel = document.getElementById('setupConfirmLabel');
const setupSubmitBtn = document.getElementById('setupSubmitBtn');
const lockOverlay = document.getElementById('lockOverlay');
const lockTitle = document.getElementById('lockTitle');
const lockHint = document.getElementById('lockHint');
const lockPwdLabel = document.getElementById('lockPwdLabel');
const lockPwdInput = document.getElementById('lockPwdInput');
const lockSubmitBtn = document.getElementById('lockSubmitBtn');
const noticeBar = document.getElementById('noticeBar');
// Debug panel DOM
const debugPanel = document.getElementById('debugPanel');
const debugContent = document.getElementById('debugContent');
const debugClearBtn = document.getElementById('debugClearBtn');

// 简单的中英文文案字典
  const I18N = {
    zh: {
    title: '本地 2FA 管家',
    add_account: '添加账号',
    reset_first_run: '重置到首次运行',
    dialog_title_add: '添加账号',
    dialog_title_edit: '编辑账号',
    label_name: '账号名称',
    label_issuer: '发行者/平台',
    label_secret: '密钥（Base32 或 Hex/MD5）',
    label_digits: '位数',
    label_period: '周期（秒）',
    label_algorithm: '算法',
    import_otpauth: '从 otpauth URL 导入',
    btn_delete: '删除',
    btn_cancel: '取消',
    btn_save: '保存',
    action_edit: '编辑',
    action_qr: '二维码',
    alg_sha1: 'SHA1（默认）',
    alg_sha256: 'SHA256',
    alg_sha512: 'SHA512',
    qr_close: '关闭',
    qr_hint_desktop: '(提示：桌面版安装 qrcode 后可生成二维码)',
    qr_hint_browser: '(提示：请在桌面版中查看二维码)',
    unnamed: '未命名',
    qr_generating: '正在生成二维码...',
    remaining: '剩余',
    invalid_secret: '密钥无效',
    qr_no_dep: '(提示：未安装二维码生成依赖，显示 URI 替代)',
      required_field: '请填写此字段'
      ,
      confirm_delete: '确定删除该账号吗？'
      ,
      master_set_title: '设置主密码',
      master_unlock_title: '解锁主密码',
      master_password: '主密码',
      master_confirm: '确认主密码',
      master_enable: '启用主密码',
      master_hint_set: '主密码用于加密保存的 2FA 密钥，请谨慎保管。',
      master_hint_unlock: '输入主密码以解锁并读取你的 2FA 账号。',
      master_required: '请输入主密码',
      master_confirm_required: '请再次输入确认密码',
      master_too_short: '主密码至少 6 位',
      master_mismatch: '两次密码不一致',
      unlock_error: '解锁失败，密码错误或数据损坏',
      unlock_required: '请输入主密码',
      set_error: '设置主密码失败',
      write_blocked: '未解锁，写入已阻止。请解锁后重试'
      ,
      copy_success: '已复制到剪贴板'
    },
    en: {
    title: 'Local 2FA Manager',
    add_account: 'Add Account',
    reset_first_run: 'Reset (First Run)',
    dialog_title_add: 'Add Account',
    dialog_title_edit: 'Edit Account',
    label_name: 'Account Name',
    label_issuer: 'Issuer/Service',
    label_secret: 'Secret (Base32 or Hex/MD5)',
    label_digits: 'Digits',
    label_period: 'Period (seconds)',
    label_algorithm: 'Algorithm',
    import_otpauth: 'Import from otpauth URL',
    btn_delete: 'Delete',
    btn_cancel: 'Cancel',
    btn_save: 'Save',
    action_edit: 'Edit',
    action_qr: 'QR Code',
    alg_sha1: 'SHA1 (default)',
    alg_sha256: 'SHA256',
    alg_sha512: 'SHA512',
    qr_close: 'Close',
    qr_hint_desktop: '(Hint: Install qrcode on desktop to generate QR)',
    qr_hint_browser: '(Hint: Please view QR in the desktop app)',
    unnamed: 'Unnamed',
    qr_generating: 'Generating QR code...',
    remaining: 'Remaining',
    invalid_secret: 'Invalid secret',
    qr_no_dep: '(Hint: QR dependency missing; showing URI as fallback)',
      required_field: 'Please fill out this field'
      ,
      confirm_delete: 'Delete this account?'
      ,
      master_set_title: 'Set Safe Password',
      master_unlock_title: 'Unlock',
      master_password: 'Safe Password',
      master_confirm: 'Confirm Password',
      master_enable: 'Enable Safe Password',
      master_hint_set: 'The safe password encrypts your 2FA secrets. Keep it safe.',
      master_hint_unlock: 'Enter safe password to unlock your accounts.',
      master_required: 'Please enter a safe password',
      master_confirm_required: 'Please confirm your password',
      master_too_short: 'Password must be at least 6 characters',
      master_mismatch: 'Passwords do not match',
      unlock_error: 'Unlock failed: wrong password or data corrupted',
      unlock_required: 'Please enter a safe password',
      set_error: 'Failed to set master password',
      write_blocked: 'Write blocked: unlock and try again.'
      ,
      copy_success: 'Copied to clipboard'
    }
  };

function getDict() {
  const lang = (state?.config?.language) || 'en';
  return I18N[lang] || I18N.en;
}

function applyI18n() {
  const d = getDict();
  try { debugLog({ event: 'i18n.apply.start', lang: (state?.config?.language) || 'en', title: d.title }); } catch (_) {}
  // 全量覆盖所有 data-i18n 节点（含动态渲染项）
  try {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (key && d[key] != null) el.textContent = d[key];
    });
  } catch (_) { /* ignore */ }
  // 同步窗口标题与 html 语言标记
  try { document.title = d.title; } catch (_) { /* ignore */ }
  // 桌面窗口标题（Tauri）
  try {
    const T = window.__TAURI__;
    const winMods = [];
    try { if (T && T.window) winMods.push(T.window); } catch (_) {}
    try { if (T && T.core && T.core.window) winMods.push(T.core.window); } catch (_) {}
    const nativeTitleText = (I18N && I18N.en && I18N.en.title) ? I18N.en.title : 'Local 2FA Manager';
    for (const wm of winMods) {
      let cur = null;
      try { if (wm && wm.appWindow) cur = wm.appWindow; } catch (_) {}
      try { if (!cur && wm && typeof wm.getCurrent === 'function') cur = wm.getCurrent(); } catch (_) {}
      if (cur && typeof cur.setTitle === 'function') {
        try { debugLog({ event: 'tauri.setTitle.start', via: (wm === (T && T.window)) ? 'window' : 'core.window', title: nativeTitleText }); } catch (_) {}
        Promise
          .resolve(cur.setTitle(nativeTitleText))
          .then(() => { try { debugLog({ event: 'tauri.setTitle.ok', title: nativeTitleText }); } catch (_) {} })
          .catch((e) => { try { debugLog({ event: 'tauri.setTitle.err', err: (e && e.message) ? e.message : String(e) }); } catch (_) {} });
        break;
      }
    }
  } catch (_) { /* ignore */ }
  // 通过 invoke 可靠设置原生窗体标题（后备方案）
  try {
    const inv = getTauriInvoke();
    if (inv) {
      const nativeTitleText = (I18N && I18N.en && I18N.en.title) ? I18N.en.title : 'Local 2FA Manager';
      try { debugLog({ event: 'tauri.invoke.set_title.start', title: nativeTitleText }); } catch (_) {}
      inv('set_title', { title: nativeTitleText })
        .then(() => { try { debugLog({ event: 'tauri.invoke.set_title.ok', title: nativeTitleText }); } catch (_) {} })
        .catch((e) => { try { debugLog({ event: 'tauri.invoke.set_title.err', err: (e && e.message) ? e.message : String(e) }); } catch (_) {} });
    } else {
      // 等待延迟注入后再调用一次
      Promise.resolve(waitForTauriInvoke(5000)).then((inv2) => {
        if (inv2) {
          const nativeTitleText = (I18N && I18N.en && I18N.en.title) ? I18N.en.title : 'Local 2FA Manager';
          try { debugLog({ event: 'tauri.invoke.set_title.late.start', title: nativeTitleText }); } catch (_) {}
          inv2('set_title', { title: nativeTitleText })
            .then(() => { try { debugLog({ event: 'tauri.invoke.set_title.late.ok', title: nativeTitleText }); } catch (_) {} })
            .catch((e) => { try { debugLog({ event: 'tauri.invoke.set_title.late.err', err: (e && e.message) ? e.message : String(e) }); } catch (_) {} });
        }
      }).catch(() => {});
    }
  } catch (_) { /* ignore */ }
  try { document.documentElement.lang = (state.config.language === 'zh' ? 'zh-CN' : 'en'); } catch (_) { /* ignore */ }
  // 语言下拉回显
  if (langSelect) langSelect.value = state.config.language;
  if (langSelectUI) {
    const valEl = langSelectUI.querySelector('.select-value');
    if (valEl) valEl.textContent = state.config.language === 'zh' ? '中文' : 'English';
  }
  // 主密码相关文案（这几个没有 data-i18n）
  if (enableMasterBtn) enableMasterBtn.textContent = d.master_enable;
  const pwdLabel = document.getElementById('masterPwdLabel');
  if (pwdLabel) pwdLabel.textContent = d.master_password;
  const confirmLabel = document.getElementById('masterConfirmLabel');
  if (confirmLabel) confirmLabel.textContent = d.master_confirm;
  // 锁屏遮罩文案
  if (lockTitle) lockTitle.textContent = d.master_unlock_title;
  if (lockHint) lockHint.textContent = d.master_hint_unlock;
  if (lockPwdLabel) lockPwdLabel.textContent = d.master_password;
  // 设置主密码遮罩文案（复用设置文案）
  if (setupTitle) setupTitle.textContent = d.master_set_title;
  if (setupHint) setupHint.textContent = d.master_hint_set;
  // 备用设置表单标签
  if (setupPwdLabel) setupPwdLabel.textContent = d.master_password;
  if (setupConfirmLabel) setupConfirmLabel.textContent = d.master_confirm;
  try { debugLog({ event: 'i18n.apply.done', lang: (state?.config?.language) || 'en' }); } catch (_) {}
}

// 记录当前标题（document 与原生窗体），便于确认是否切换成功
async function logCurrentTitle(ctx = 'title.info') {
  try {
    const dict = (() => { try { return getDict(); } catch (_) { return null; } })();
    const docTitle = (() => { try { return document.title || ''; } catch (_) { return ''; } })();
    const T = (() => { try { return window.__TAURI__; } catch (_) { return null; } })();
    const hasTauriObj = !!T;
    const hasWinModule = !!(T && (T.window || (T.core && T.core.window)));
    let hasSetTitleFn = false;
    try {
      const wm = T && (T.window || (T.core && T.core.window));
      let cur = null;
      try { if (wm && wm.appWindow) cur = wm.appWindow; } catch (_) {}
      try { if (!cur && wm && typeof wm.getCurrent === 'function') cur = wm.getCurrent(); } catch (_) {}
      hasSetTitleFn = !!(cur && typeof cur.setTitle === 'function');
    } catch (_) {}
    let cfgTitle = null;
    let nativeTitle = null;
    let inv = null;
    try { inv = getTauriInvoke(); } catch (_) { inv = null; }
    if (inv) {
      // 从配置推断预期标题
      try {
        const text = await inv('read_config');
        if (typeof text === 'string') {
          const v = JSON.parse(text || '{}');
          const lang = (v && v.language) ? v.language : (state?.config?.language || 'en');
          cfgTitle = (lang === 'zh') ? '本地 2FA 管家' : 'Local 2FA Manager';
        }
      } catch (_) {}
      // 若原生提供 get_title，则读取实际窗体标题
      try {
        const t = await inv('get_title');
        if (typeof t === 'string') nativeTitle = t;
      } catch (_) { /* ignore missing command in browser or old build */ }
    }
    debugLog({
      event: 'title.current',
      ctx,
      doc_title: docTitle,
      dict_title: dict ? dict.title : null,
      cfg_title: cfgTitle,
      native_title: nativeTitle,
      tauri: !!inv,
      tauri_obj: hasTauriObj,
      tauri_win: hasWinModule,
      tauri_setTitle_fn: hasSetTitleFn
    });
  } catch (_) { /* ignore */ }
}

// 在调试日志中直观显示 Tauri 注入/就绪状态
function logTauriStatus(ctx = 'tauri.status') {
  try {
    const T = (() => { try { return window.__TAURI__; } catch (_) { return null; } })();
    const hasObj = !!T;
    let hasInvoke = false;
    try { hasInvoke = !!getTauriInvoke(); } catch (_) { hasInvoke = false; }
    const hasCoreInvoke = !!(T && T.core && typeof T.core.invoke === 'function');
    const hasTauriInvoke = !!(T && T.tauri && typeof T.tauri.invoke === 'function');
    const hasWinModule = !!(T && (T.window || (T.core && T.core.window)));
    let hasSetTitleFn = false;
    try {
      const wm = T && (T.window || (T.core && T.core.window));
      let cur = null;
      try { if (wm && wm.appWindow) cur = wm.appWindow; } catch (_) {}
      try { if (!cur && wm && typeof wm.getCurrent === 'function') cur = wm.getCurrent(); } catch (_) {}
      hasSetTitleFn = !!(cur && typeof cur.setTitle === 'function');
    } catch (_) {}
    debugLog({
      event: 'tauri.status',
      ctx,
      obj: hasObj,
      invoke: hasInvoke,
      core_invoke: hasCoreInvoke,
      tauri_invoke: hasTauriInvoke,
      window_module: hasWinModule,
      setTitle_fn: hasSetTitleFn,
      ready: hasInvoke
    });
  } catch (_) { /* ignore */ }
}

// 表单校验消息国际化：用自定义消息替换浏览器默认文案
function setupFormValidationI18n() {
  const inputs = [labelInput, secretInput].filter(Boolean);
  inputs.forEach((inp) => {
    // invalid 时设置对应语言的提示
    inp.addEventListener('invalid', (e) => {
      try {
        const d = getDict();
        e.target.setCustomValidity(d.required_field || '');
      } catch (_) { /* ignore */ }
    });
    // 输入变更时清除自定义提示，恢复校验
    inp.addEventListener('input', (e) => {
      try { e.target.setCustomValidity(''); } catch (_) { /* ignore */ }
    });
  });
}

async function loadFromBridge() {
  // 优先使用 Tauri sidecar，其次使用 pywebview 桥接
  if (tauriProcess) {
    try {
      const res = await execSidecar(['read']);
      if (res.code === 0) {
        const data = JSON.parse(res.stdout || '[]');
        if (Array.isArray(data)) return data;
        return [];
      }
    } catch (_) { /* fall through */ }
  }
  if (!bridge) return null;
  try {
    const data = await bridge.read_accounts();
    if (Array.isArray(data)) return data;
    return [];
  } catch (_) { return null; }
}

function loadFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) state.accounts = parsed;
  } catch (e) {
    console.warn('读取本地存储失败', e);
  }
}

function applyConfig() {
  try {
    const accent = state?.config?.accent;
    if (accent) document.documentElement.style.setProperty('--accent', accent);
  } catch (_) { /* ignore */ }
}

async function loadConfig() {
  let cfg = null;
  const inv = getTauriInvoke();
  if (inv) {
    try {
      const res = await inv('read_config');
      if (typeof res === 'string' && res.trim()) cfg = JSON.parse(res);
      else if (res && typeof res === 'object') cfg = res;
    } catch (_) { /* ignore */ }
  } else if (tauriProcess) {
    try {
      const r = await execSidecar(['config-read']);
      if (r.code === 0) cfg = JSON.parse(r.stdout || '{}');
    } catch (_) { /* ignore */ }
  }
  if (!cfg) {
    try {
      const raw = localStorage.getItem(CONFIG_KEY);
      if (raw) cfg = JSON.parse(raw);
    } catch (_) { /* ignore */ }
  }
  if (!cfg || typeof cfg !== 'object') cfg = {};
  state.config = {
    accent: cfg.accent || state.config.accent,
    language: cfg.language || state.config.language
  };
  applyConfig();
}

async function saveConfig() {
  const json = JSON.stringify(state.config);
  const inv = getTauriInvoke();
  if (inv) {
    try {
      try { debugLog({ event: 'tauri.invoke.write_config.start', bytes: json.length }); } catch (_) {}
      await inv('write_config', { data: json });
      try { debugLog({ event: 'tauri.invoke.write_config.ok' }); } catch (_) {}
    } catch (e) {
      try { debugLog({ event: 'tauri.invoke.write_config.err', msg: (e && e.message) ? e.message : e }, 'error'); } catch (_) {}
    }
    return;
  }
  if (tauriProcess) {
    try {
      try { debugLog({ event: 'sidecar.config_write.start', bytes: json.length }); } catch (_) {}
      await execSidecar(['config-write'], { stdin: json });
      try { debugLog({ event: 'sidecar.config_write.ok' }); } catch (_) {}
    } catch (e) {
      try { debugLog({ event: 'sidecar.config_write.err', msg: (e && e.message) ? e.message : e }, 'error'); } catch (_) {}
    }
    return;
  }
  try { localStorage.setItem(CONFIG_KEY, json); } catch (_) { /* ignore */ }
}

// 语言切换
langSelect && langSelect.addEventListener('change', async () => {
  try { debugLog({ event: 'lang.change', value: langSelect.value || 'en' }); } catch (_) {}
  // 切换前记录一次标题（document/native），用于对比
  try { await logCurrentTitle('lang.change.before'); } catch (_) {}
  try { logTauriStatus('lang.change.before'); } catch (_) {}
  state.config.language = langSelect.value || 'en';
  await saveConfig();
  applyI18n();
  renderAccounts();
  await logCurrentTitle('lang.change.after');
  try { logTauriStatus('lang.change.after'); } catch (_) {}
  try { debugLog({ event: 'lang.change.done', value: state.config.language || 'en' }); } catch (_) {}
});

// 自定义语言选择器交互
function setupLangSelectUI() {
  if (!langSelectUI) return;
  const menu = langSelectUI.querySelector('.select-menu');
  const valEl = langSelectUI.querySelector('.select-value');
  const setOpen = (open) => {
    langSelectUI.classList.toggle('open', !!open);
    langSelectUI.setAttribute('aria-expanded', open ? 'true' : 'false');
  };
  // 切换展开
  langSelectUI.addEventListener('click', (e) => {
    if (e.target && menu && menu.contains(e.target)) return; // 点击菜单项单独处理
    setOpen(!langSelectUI.classList.contains('open'));
  });
  // 菜单项选择
  if (menu) {
    menu.querySelectorAll('li[role="option"]').forEach(li => {
      li.addEventListener('click', async () => {
        const v = li.getAttribute('data-value') || 'en';
        try { debugLog({ event: 'lang.ui.select', value: v }); } catch (_) {}
        if (valEl) valEl.textContent = v === 'zh' ? '中文' : 'English';
        setOpen(false);
        if (langSelect) {
          langSelect.value = v;
          langSelect.dispatchEvent(new Event('change', { bubbles: true }));
        } else {
          // 直接应用前记录一次标题
          try { await logCurrentTitle('lang.ui.select.before'); } catch (_) {}
          state.config.language = v;
          await saveConfig();
          applyI18n();
          renderAccounts();
          await logCurrentTitle('lang.ui.select.after');
          try { debugLog({ event: 'lang.ui.select.applied', value: state.config.language || 'en' }); } catch (_) {}
        }
      });
    });
  }
  // 外部点击关闭
  document.addEventListener('click', (e) => {
    if (!langSelectUI.contains(e.target)) setOpen(false);
  });
  // 初始化显示
  if (valEl) valEl.textContent = state.config.language === 'zh' ? '中文' : 'English';
}

async function saveViaBridge() {
  if (tauriProcess) {
    try {
      const res = await execSidecar(['write'], { stdin: JSON.stringify(state.accounts) });
      return res.code === 0;
    } catch (_) { /* fall through */ }
  }
  if (!bridge) return false;
  try { return await bridge.write_accounts(state.accounts); } catch (_) { return false; }
}

function saveToStorage() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.accounts));
  } catch (e) {
    console.warn('保存本地存储失败', e);
  }
}

function updateFileStatus() {
  if (!fileStatusEl) return;
  if (getTauriInvoke()) {
    fileStatusEl.textContent = 'Tauri：使用应用数据目录 data.json';
  } else if (tauriProcess) {
    fileStatusEl.textContent = 'Tauri sidecar：使用 data.json';
  } else if (bridge) {
    fileStatusEl.textContent = 'Python 桥接：使用 data.json';
  } else if (state.fileHandle) {
    fileStatusEl.textContent = `已绑定文件：${state.fileHandle.name || '已选择'}`;
  } else {
    fileStatusEl.textContent = '未绑定文件';
  }
}

async function saveToCurrentFile() {
  try {
    if (!state.fileHandle) return;
    const writable = await state.fileHandle.createWritable();
    await writable.write(JSON.stringify(state.accounts, null, 2));
    await writable.close();
  } catch (e) {
    if (e && e.name === 'AbortError') return;
    alert('保存到文件失败：' + (e && e.message ? e.message : e));
  }
}

async function persistAccounts() {
  const d = getDict();
  try { debugLog({ event: 'persistAccounts.start', count: state.accounts.length }); } catch (_) {}
  // 优先 Tauri 原生命令，其次 Python 桥接，其次文件句柄，最后 localStorage
  const inv = getTauriInvoke();
  if (inv) {
    try {
      try { debugLog({ event: 'persistAccounts.backend', type: 'tauriInvoke' }); } catch (_) {}
      // 若启用了主密码且当前处于锁定状态，则阻止写入并提示解锁
      const enc = await inv('is_encrypted');
      try { debugLog({ event: 'persistAccounts.is_encrypted', enc }); } catch (_) {}
      let locked = false;
      if (enc) {
        locked = await inv('is_locked');
      }
      try { debugLog({ event: 'persistAccounts.is_locked', locked }); } catch (_) {}
      if (enc && locked === true) {
        lastError = 'locked';
        try { showLockOverlay(); } catch (_) {}
        try { showNotice((d.write_blocked || 'Write blocked: unlock and try again.') + (lastError ? ` (${lastError})` : '')); } catch (_) {}
        console.warn('写入失败：主密码未解锁');
        try { debugLog({ event: 'persistAccounts.blocked', reason: 'locked' }, 'warn'); } catch (_) {}
        return false;
      }
      const dataStr = JSON.stringify(state.accounts);
      try { debugLog({ event: 'persistAccounts.write', bytes: dataStr.length }); } catch (_) {}
      await inv('write_accounts', { data: dataStr });
      // 成功写入后再更新浏览器缓存，避免缓存覆盖真实状态
      saveToStorage();
      try { debugLog('persistAccounts.success'); } catch (_) {}
      return true;
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      lastError = msg;
      console.warn('写入账户失败', e);
      try { showNotice(`Save failed: ${msg}`); } catch (_) {}
      try { debugLog({ event: 'persistAccounts.error', msg, err: e }, 'error'); } catch (_) {}
      return false;
    }
  } else if (bridge) {
    try {
      try { debugLog({ event: 'persistAccounts.backend', type: 'bridge' }); } catch (_) {}
      await saveViaBridge();
      saveToStorage(); // 作为快速缓存
      try { debugLog('persistAccounts.success.bridge'); } catch (_) {}
      return true;
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      lastError = msg;
      console.warn('桥接写入失败', e);
      try { showNotice(`Save failed: ${msg}`); } catch (_) {}
      try { debugLog({ event: 'persistAccounts.error.bridge', msg, err: e }, 'error'); } catch (_) {}
      return false;
    }
  } else if (state.fileHandle) {
    try {
      try { debugLog({ event: 'persistAccounts.backend', type: 'fileHandle' }); } catch (_) {}
      await saveToCurrentFile();
      saveToStorage();
      try { debugLog('persistAccounts.success.file'); } catch (_) {}
      return true;
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      lastError = msg;
      console.warn('文件句柄写入失败', e);
      try { showNotice(`Save failed: ${msg}`); } catch (_) {}
      try { debugLog({ event: 'persistAccounts.error.file', msg, err: e }, 'error'); } catch (_) {}
      return false;
    }
  } else {
    try {
      try { debugLog({ event: 'persistAccounts.backend', type: 'localStorage' }); } catch (_) {}
      saveToStorage();
      try { debugLog('persistAccounts.success.local'); } catch (_) {}
      return true;
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      lastError = msg;
      console.warn('本地缓存写入失败', e);
      try { showNotice(`Save failed: ${msg}`); } catch (_) {}
      try { debugLog({ event: 'persistAccounts.error.local', msg, err: e }, 'error'); } catch (_) {}
      return false;
    }
  }
}

// 主密码：展示设置弹窗
function showSetMasterDialog(opts = {}) {
  const force = !!opts.force;
  const d = getDict();
  if (!masterDialog) return;
  const hasTauri = !!getTauriInvoke();
  // 仅在桌面环境（Tauri）中强制遮罩与设置主密码
  if (hasTauri || force) {
    try {
      document.body.classList.add('locked');
      if (setupOverlay) setupOverlay.classList.add('show');
    } catch (_) {}
  } else {
    // 非桌面（浏览器预览）不弹设置流程，避免调用不存在的 API
    try { debugLog({ event: 'master.set.skipped.browser' }, 'warn'); } catch (_) {}
    // 在无法使用 <dialog> 或原生 API 时，直接激活遮罩内备用表单
    try {
      if (setupOverlay) setupOverlay.classList.add('show');
      if (setupPwdRow) setupPwdRow.style.display = '';
      if (setupConfirmRow) setupConfirmRow.style.display = '';
      if (setupSubmitBtn) setupSubmitBtn.style.display = '';
      if (setupPwdInput) setTimeout(() => { try { setupPwdInput.focus(); } catch (_) {} }, 0);
      bindSetupFallbackSubmit();
    } catch (_) {}
  }
  if (masterTitle) masterTitle.textContent = d.master_set_title;
  if (masterConfirmRow) masterConfirmRow.style.display = '';
  if (masterHint) masterHint.textContent = d.master_hint_set;
  if (masterPwdInput) masterPwdInput.value = '';
  if (masterConfirmInput) masterConfirmInput.value = '';
  // 禁止 ESC 关闭
  try {
    if (!masterDialog.__nonCancelableBound) {
      masterDialog.addEventListener('cancel', (e) => { e.preventDefault(); });
      masterDialog.__nonCancelableBound = true;
    }
  } catch (_) {}
  // 桌面环境：为避免 WebView 堆叠上下文问题，先隐藏遮罩再显示弹窗
  if (hasTauri) {
    try { setupOverlay && setupOverlay.classList.remove('show'); } catch (_) {}
    // 弹窗显示：若 showModal 不可用或失败，使用后备方案
    try {
      if (typeof masterDialog.showModal === 'function') {
        masterDialog.showModal();
      } else {
        masterDialog.setAttribute('open', '');
        masterDialog.style.display = 'block';
      }
    } catch (_) {
      try {
        masterDialog.setAttribute('open', '');
        masterDialog.style.display = 'block';
      } catch (_) {}
    }
  }
  // 若弹窗未正确展示，强制回退并记录调试信息
  if (hasTauri) {
    try {
      setTimeout(() => {
        try {
          const rect = masterDialog.getBoundingClientRect();
          const shown = !!rect && rect.width > 10 && rect.height > 10;
          debugLog({ event: 'master.dialog.state', open: !!masterDialog.open, shown, rect: { w: rect.width, h: rect.height } });
          if (!shown) {
            // 启用遮罩内备用设置表单
            try {
              document.body.classList.add('locked');
              if (setupOverlay) setupOverlay.classList.add('show');
              if (setupPwdRow) setupPwdRow.style.display = '';
              if (setupConfirmRow) setupConfirmRow.style.display = '';
              if (setupSubmitBtn) setupSubmitBtn.style.display = '';
              if (setupPwdInput) setTimeout(() => { try { setupPwdInput.focus(); } catch (_) {} }, 0);
              // 绑定一次提交逻辑
              if (setupSubmitBtn && !setupSubmitBtn.__boundSubmit) {
                setupSubmitBtn.__boundSubmit = true;
                setupSubmitBtn.addEventListener('click', async () => {
                  const pwd = (setupPwdInput?.value || '').trim();
                  const pwd2 = (setupConfirmInput?.value || '').trim();
                  const d2 = getDict();
                  if (!pwd || pwd.length < 6) { alert(d2.required_field); return; }
                  if (pwd !== pwd2) { alert(d2.master_mismatch); return; }
                  try {
                    const inv3 = getTauriInvoke();
                    await inv3('set_master_password', { password: pwd });
                    try {
                      if (setupOverlay) setupOverlay.classList.remove('show');
                      document.body.classList.remove('locked');
                    } catch (_) {}
                    await persistAccounts();
                    // 设置完成后，主动锁定后端内存密钥，确保立即进入解锁流程
                    try { await inv3('lock'); } catch (_) {}
                    try {
                      const lang = (state && state.config && state.config.language) || 'en';
                      showNotice(lang === 'zh' ? '设置主密码成功' : 'Master password set successfully');
                    } catch (_) {}
                    try { showLockOverlay(); } catch (_) {}
                  } catch (e) {
                    alert(d2.set_error + (e && e.message ? (': ' + e.message) : ''));
                  }
                });
              }
            } catch (_) {}
          }
        } catch (_) {}
      }, 50);
    } catch (_) {}
  }
  // 聚焦密码输入框以便立即输入
  try { setTimeout(() => { try { masterPwdInput && masterPwdInput.focus(); } catch (_) {} }, 0); } catch (_) {}
  masterForm.onsubmit = async (evt) => {
    const isCancel = evt && evt.submitter && evt.submitter.value === 'cancel';
    if (isCancel) { evt.preventDefault(); return; }
    evt.preventDefault();
    const pwd = (masterPwdInput?.value || '').trim();
    const pwd2 = (masterConfirmInput?.value || '').trim();
    if (!pwd) { try { showNotice(d.master_required); } catch (_) {} return; }
    if (pwd.length < 6) { try { showNotice(d.master_too_short); } catch (_) {} return; }
    if (!pwd2) { try { showNotice(d.master_confirm_required); } catch (_) {} return; }
    if (pwd !== pwd2) { try { showNotice(d.master_mismatch); } catch (_) {} return; }
    // 等待原生 API 注入，避免“未就绪”导致点击无效
    const inv2 = await waitForTauriInvoke(4000);
    try { debugLog({ event: 'master.tauri_ready', ready: !!inv2 }); } catch (_) {}
    if (!inv2) {
      if (force) {
        // 浏览器模拟模式：不调用后端，仅关闭遮罩并记录日志
        try { debugLog({ event: 'master.set.simulated' }); } catch (_) {}
        try {
          masterDialog.close();
          if (setupOverlay) setupOverlay.classList.remove('show');
          document.body.classList.remove('locked');
        } catch (_) {}
        return;
      } else {
        // 桌面类环境但原生 API 仍未就绪：明确提示
        try { debugLog({ event: 'master.set.error', path: 'dialog', msg: 'Tauri API not ready' }, 'error'); } catch (_) {}
        try { showNotice(d.set_error + ': Tauri API not ready'); } catch (_) {}
        try {
          masterDialog.close();
          if (setupOverlay) setupOverlay.classList.remove('show');
          document.body.classList.remove('locked');
        } catch (_) {}
        return;
      }
    }
    try {
      try { debugLog({ event: 'master.set.submit', via: 'dialog' }); } catch (_) {}
      try { debugLog({ event: 'invoke.set_master_password.start', via: 'dialog' }); } catch (_) {}
      await inv2('set_master_password', { password: pwd });
      try { debugLog({ event: 'invoke.set_master_password.ok', via: 'dialog' }); } catch (_) {}
      masterDialog.close();
      try { debugLog({ event: 'ui.masterDialog.closed' }); } catch (_) {}
      // 设置完成后关闭遮罩
      try {
        if (setupOverlay) setupOverlay.classList.remove('show');
        document.body.classList.remove('locked');
        try { debugLog({ event: 'ui.overlay.closed' }); } catch (_) {}
      } catch (_) {}
      // 写入当前内存的账户（会被加密保存）
      const persistOk = await persistAccounts();
      try { debugLog({ event: 'persist.after', ok: !!persistOk }); } catch (_) {}
      // 设置完成后，主动锁定后端内存密钥，确保立即进入解锁流程
      try { await inv2('lock'); } catch (_) {}
      try {
        const lang = (state && state.config && state.config.language) || 'en';
        showNotice(lang === 'zh' ? '设置主密码成功' : 'Master password set successfully');
        try { debugLog({ event: 'notice.shown', type: 'master_set_success' }); } catch (_) {}
      } catch (_) {}
      try {
        showUnlockDialog();
        try { debugLog({ event: 'ui.showUnlockDialog.called' }); } catch (_) {}
      } catch (_) {
        try { showLockOverlay(); } catch (_) {}
      }
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      try { console.error('set_master_password failed (dialog path):', e); } catch (_) {}
      try { debugLog({ event: 'master.set.error', path: 'dialog', msg }, 'error'); } catch (_) {}
      try { showNotice(d.set_error + (msg ? (': ' + msg) : '')); } catch (_) {}
    }
  };

  // 兼容某些 WebView 对 <form method="dialog"> 的事件行为：
  // 若未触发 submit，则显式为 OK 按钮绑定点击，转发为一次提交。
  try {
    if (masterSubmitBtn && !masterSubmitBtn.__boundClick) {
      masterSubmitBtn.__boundClick = true;
      masterSubmitBtn.addEventListener('click', async (e) => {
        try { e.preventDefault(); e.stopPropagation(); } catch (_) {}
        try { debugLog({ event: 'master.submit.click', via: 'dialog-click', open: !!masterDialog?.open }); } catch (_) {}

        const d2 = getDict();
        const pwd = (masterPwdInput?.value || '').trim();
        const pwd2 = (masterConfirmInput?.value || '').trim();
        if (!pwd) { try { showNotice(d2.master_required); } catch (_) {} try { debugLog({ event: 'master.required_field' }); } catch (_) {} return; }
        if (pwd.length < 6) { try { showNotice(d2.master_too_short); } catch (_) {} try { debugLog({ event: 'master.too_short' }); } catch (_) {} return; }
        if (!pwd2) { try { showNotice(d2.master_confirm_required); } catch (_) {} try { debugLog({ event: 'master.confirm_required' }); } catch (_) {} return; }
        if (pwd !== pwd2) { try { showNotice(d2.master_mismatch); } catch (_) {} try { debugLog({ event: 'master.not_match' }); } catch (_) {} return; }

        const inv = await waitForTauriInvoke(4000);
        try { debugLog({ event: 'master.tauri_ready', ready: !!inv, via: 'dialog-click' }); } catch (_) {}

        if (!inv) {
          if (masterDialog?.open) { try { masterDialog.close(); try { debugLog({ event: 'ui.masterDialog.closed' }); } catch (_) {} } catch (_) {} }
          try {
            document.body.classList.remove('locked');
            setupOverlay && setupOverlay.classList.remove('show');
            try { debugLog({ event: 'ui.overlay.closed' }); } catch (_) {}
          } catch (_) {}

          const ok = await persistAccounts();
          try { debugLog({ event: 'persist.after', ok: !!ok, via: 'dialog-click' }); } catch (_) {}
          try {
            const lang = (state && state.config && state.config.language) || 'en';
            showNotice(lang === 'zh' ? '设置主密码成功' : 'Master password set successfully');
            try { debugLog({ event: 'notice.shown', type: 'master_set_success', via: 'dialog-click' }); } catch (_) {}
          } catch (_) {}
          try {
            await showUnlockDialog({ force: true });
            try { debugLog({ event: 'ui.showUnlockDialog.called', via: 'browser' }); } catch (_) {}
          } catch (_) {
            try { showLockOverlay(); } catch (_) {}
          }
          return;
        }

        try {
          try { debugLog({ event: 'master.set.submit', via: 'dialog-click' }); } catch (_) {}
          try { debugLog({ event: 'invoke.set_master_password.start', via: 'dialog-click' }); } catch (_) {}
          await inv('set_master_password', { password: pwd });
          try { debugLog({ event: 'invoke.set_master_password.ok', via: 'dialog-click' }); } catch (_) {}
        } catch (e2) {
          const msg2 = (e2 && e2.message) ? e2.message : (typeof e2 === 'string' ? e2 : (e2 && e2.toString ? e2.toString() : 'unknown error'));
          try { console.error('set_master_password failed (dialog-click path):', e2); } catch (_) {}
          try { debugLog({ event: 'master.set.error', path: 'dialog-click', msg: msg2 }, 'error'); } catch (_) {}
          try { showNotice(d2.set_error + (msg2 ? (': ' + msg2) : '')); } catch (_) {}
          return;
        }

        if (masterDialog?.open) { try { masterDialog.close(); try { debugLog({ event: 'ui.masterDialog.closed' }); } catch (_) {} } catch (_) {} }
        try {
          document.body.classList.remove('locked');
          setupOverlay && setupOverlay.classList.remove('show');
          try { debugLog({ event: 'ui.overlay.closed' }); } catch (_) {}
        } catch (_) {}

        const ok2 = await persistAccounts();
        try { debugLog({ event: 'persist.after', ok: !!ok2, via: 'dialog-click' }); } catch (_) {}
        try {
          const lang = (state && state.config && state.config.language) || 'en';
          showNotice(lang === 'zh' ? '设置主密码成功' : 'Master password set successfully');
          try { debugLog({ event: 'notice.shown', type: 'master_set_success', via: 'dialog-click' }); } catch (_) {}
        } catch (_) {}
        try {
          await showUnlockDialog();
          try { debugLog({ event: 'ui.showUnlockDialog.called', via: 'dialog-click' }); } catch (_) {}
        } catch (_) {
          try { showLockOverlay(); } catch (_) {}
        }
      });
    }
    if (masterDialog && !masterDialog.__boundCloseLog) {
      masterDialog.__boundCloseLog = true;
      masterDialog.addEventListener('close', () => {
        try { debugLog({ event: 'master.dialog.close', returnValue: masterDialog.returnValue, open: !!masterDialog.open }); } catch (_) {}
      });
    }
  } catch (_) {}
}

// 绑定一次遮罩内备用设置表单的提交逻辑
function bindSetupFallbackSubmit() {
  if (!setupSubmitBtn || setupSubmitBtn.__boundSubmit) return;
  setupSubmitBtn.__boundSubmit = true;
  setupSubmitBtn.addEventListener('click', async () => {
    const d = getDict();
    const pwd = (setupPwdInput?.value || '').trim();
    const pwd2 = (setupConfirmInput?.value || '').trim();
    if (!pwd) { try { showNotice(d.master_required); } catch (_) {} return; }
    if (pwd.length < 6) { try { showNotice(d.master_too_short); } catch (_) {} return; }
    if (!pwd2) { try { showNotice(d.master_confirm_required); } catch (_) {} return; }
    if (pwd !== pwd2) { try { showNotice(d.master_mismatch); } catch (_) {} return; }
    const inv = await waitForTauriInvoke(4000);
    try { debugLog({ event: 'master.tauri_ready', ready: !!inv, via: 'overlay' }); } catch (_) {}
    if (!inv) {
      const tauriInjected = !!(window && window.__TAURI__);
      if (!tauriInjected) {
        try { debugLog({ event: 'master.set.simulated.overlay', tauriInjected }); } catch (_) {}
        try {
          if (setupOverlay) setupOverlay.classList.remove('show');
          document.body.classList.remove('locked');
          try { debugLog({ event: 'ui.overlay.closed' }); } catch (_) {}
        } catch (_) {}
        const okSim = await persistAccounts();
        try { debugLog({ event: 'persist.after', ok: !!okSim, via: 'overlay' }); } catch (_) {}
        try {
          const lang = (state && state.config && state.config.language) || 'en';
          showNotice(lang === 'zh' ? '设置主密码成功' : 'Master password set successfully');
          try { debugLog({ event: 'notice.shown', type: 'master_set_success', via: 'overlay' }); } catch (_) {}
        } catch (_) {}
        // 纯浏览器预览：记录主密码哈希用于后续解锁校验，并标记完成设置
        try {
          const hash = await sha256Hex(pwd);
          localStorage.setItem(PREVIEW_MASTER_HASH_KEY, hash);
          localStorage.setItem(PREVIEW_SETUP_DONE_KEY, '1');
          try { debugLog({ event: 'preview.master_hash.saved' }); } catch (_) {}
        } catch (_) {}
        // 设置完成后立即进入解锁流程，确保后续每次打开都需验证
        try { showLockOverlay(); } catch (_) {}
        return;
      }
      try { debugLog({ event: 'master.set.error', path: 'overlay', msg: 'Tauri API not ready', tauriInjected }, 'error'); } catch (_) {}
      try { showNotice(d.set_error + ': Tauri API not ready'); } catch (_) {}
      return;
    }
    try {
      try { debugLog({ event: 'master.set.submit', via: 'overlay' }); } catch (_) {}
      try { debugLog({ event: 'invoke.set_master_password.start', via: 'overlay' }); } catch (_) {}
      await inv('set_master_password', { password: pwd });
      try { debugLog({ event: 'invoke.set_master_password.ok', via: 'overlay' }); } catch (_) {}
      try {
        if (setupOverlay) setupOverlay.classList.remove('show');
        document.body.classList.remove('locked');
        try { debugLog({ event: 'ui.overlay.closed' }); } catch (_) {}
      } catch (_) {}
      const persistOk = await persistAccounts();
      try { debugLog({ event: 'persist.after', ok: !!persistOk, via: 'overlay' }); } catch (_) {}
      // 设置完成后，主动锁定后端内存密钥，确保立即进入解锁流程
      try { await inv('lock'); } catch (_) {}
      try {
        const lang = (state && state.config && state.config.language) || 'en';
        showNotice(lang === 'zh' ? '设置主密码成功' : 'Master password set successfully');
        try { debugLog({ event: 'notice.shown', type: 'master_set_success', via: 'overlay' }); } catch (_) {}
      } catch (_) {}
      try { showLockOverlay(); } catch (_) {}
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      try { console.error('set_master_password failed (overlay path):', e); } catch (_) {}
      try { debugLog({ event: 'master.set.error', path: 'overlay', msg }, 'error'); } catch (_) {}
      try { showNotice(d.set_error + (msg ? (': ' + msg) : '')); } catch (_) {}
    }
  });
}

// 主密码：展示解锁弹窗
function showUnlockDialog() {
  const d = getDict();
  if (!masterDialog) return;
  if (masterTitle) masterTitle.textContent = d.master_unlock_title;
  if (masterConfirmRow) masterConfirmRow.style.display = 'none';
  if (masterHint) masterHint.textContent = d.master_hint_unlock;
  if (masterPwdInput) masterPwdInput.value = '';
  // 清理并替换提交按钮，避免沿用“设置主密码”的点击监听
  try {
    const btn = document.getElementById('masterSubmitBtn');
    if (btn) {
      const newBtn = btn.cloneNode(true);
      // 在解锁模式下让按钮触发表单提交
      try { newBtn.setAttribute('type', 'submit'); } catch (_) {}
      btn.parentNode && btn.parentNode.replaceChild(newBtn, btn);
    }
  } catch (_) {}
  // 避免遮罩与弹窗堆叠导致输入不可见
  try { lockOverlay && lockOverlay.classList.remove('show'); } catch (_) {}
  masterDialog.showModal();
  masterForm.onsubmit = async (evt) => {
    const isCancel = evt && evt.submitter && evt.submitter.value === 'cancel';
    if (isCancel) return;
    evt.preventDefault();
    const pwd = (masterPwdInput?.value || '').trim();
    if (!pwd || pwd.length < 6) { alert(d.required_field); return; }
    try {
      const inv = getTauriInvoke();
      const text = await inv('unlock', { password: pwd });
      const data = JSON.parse(typeof text === 'string' ? text : '[]');
      state.accounts = Array.isArray(data) ? data : [];
      masterDialog.close();
      renderAccounts();
    } catch (e) {
      const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
      try { console.error('unlock failed (dialog path):', e); } catch (_) {}
      try { debugLog({ event: 'unlock.error', path: 'dialog', msg }, 'error'); } catch (_) {}
      alert(d.unlock_error + (msg ? (': ' + msg) : ''));
    }
  };
}

// 锁屏遮罩：强制解锁后再加载内容
function showLockOverlay() {
  document.body.classList.add('locked');
  if (lockOverlay) lockOverlay.classList.add('show');
  if (lockPwdInput) {
    lockPwdInput.value = '';
    // 延迟聚焦以确保元素可见
    setTimeout(() => { try { lockPwdInput.focus(); } catch (_) {} }, 0);
  }
}
function hideLockOverlay() {
  document.body.classList.remove('locked');
  if (lockOverlay) lockOverlay.classList.remove('show');
}

// 简易调试打印：将消息以时间戳追加到页面左下角调试面板
function debugLog(msg, level = 'info') {
  try {
    const ts = new Date().toISOString();
    let text = '';
    if (msg === undefined) {
      text = '(undefined)';
    } else if (msg === null) {
      text = '(null)';
    } else if (typeof msg === 'object') {
      try { text = JSON.stringify(msg); } catch (_) { text = String(msg); }
    } else {
      text = String(msg);
    }
    const line = `[${ts}] [${level}] ${text}`;
    // 追加到页面调试面板（若存在）
    try {
      if (debugContent) {
        const div = document.createElement('div');
        div.textContent = line;
        debugContent.appendChild(div);
        try { debugContent.scrollTop = debugContent.scrollHeight; } catch (_) {}
        try { if (debugPanel) debugPanel.style.display = 'block'; } catch (_) {}
      }
    } catch (_) {}
    // 同步到浏览器控制台
    try {
      const lc = String(level || 'info').toLowerCase();
      if (lc === 'error') console.error(text);
      else if (lc === 'warn') console.warn(text);
      else console.log(text);
    } catch (_) {}
    // 在 Tauri 环境下，同步所有日志到终端
    try {
      const inv = getTauriInvoke();
      if (inv) {
        inv('emit_log', { level, message: line }).catch(() => {});
      }
    } catch (_) {}
  } catch (_) {}
}

function showNotice(msg, timeout = 4000) {
  if (!noticeBar) return;
  try {
    noticeBar.textContent = msg || '';
    noticeBar.style.display = 'block';
    try { debugLog(`[notice] ${msg}`); } catch (_) {}
  } catch (_) {}
  if (timeout > 0) {
    try { clearTimeout(showNotice._t); } catch (_) {}
    showNotice._t = setTimeout(() => { try { hideNotice(); } catch (_) {} }, timeout);
  }
}

function hideNotice() {
  if (!noticeBar) return;
  try {
    noticeBar.style.display = 'none';
    noticeBar.textContent = '';
  } catch (_) {}
}

// 绑定清空调试面板按钮
debugClearBtn && debugClearBtn.addEventListener('click', () => {
  try {
    if (debugContent) debugContent.innerHTML = '';
  } catch (_) {}
});

noticeBar && noticeBar.addEventListener('click', () => { try { hideNotice(); } catch (_) {} });


lockSubmitBtn && lockSubmitBtn.addEventListener('click', async () => {
  const d = getDict();
  const pwd = (lockPwdInput?.value || '').trim();
  if (!pwd) { try { showNotice(d.unlock_required); } catch (_) {} return; }
  if (pwd.length < 6) { try { showNotice(d.master_too_short); } catch (_) {} return; }
  // 浏览器模拟模式：当 URL 参数 simulate=lock/encrypted 时，允许本地模拟解锁
  if (!getTauriInvoke()) {
    let sim = null;
    try { sim = new URLSearchParams(location.search).get('simulate'); } catch (_) {}
    if (sim === 'lock' || sim === 'encrypted') {
      try { debugLog({ event: 'unlock.simulated' }); } catch (_) {}
      hideLockOverlay();
      try { hideNotice(); } catch (_) {}
      loadFromStorage();
      renderAccounts();
      updateFileStatus();
      return;
    }
    // 预览模式正式校验：比对保存的主密码哈希
    try {
      const saved = localStorage.getItem(PREVIEW_MASTER_HASH_KEY);
      if (saved) {
        const hash = await sha256Hex(pwd);
        if (hash === saved) {
          try { debugLog({ event: 'unlock.preview.ok' }); } catch (_) {}
          hideLockOverlay();
          try { hideNotice(); } catch (_) {}
          loadFromStorage();
          renderAccounts();
          updateFileStatus();
          return;
        } else {
          const dct = getDict();
          try { showNotice(dct.unlock_error); } catch (_) {}
          try { debugLog({ event: 'unlock.preview.fail' }, 'warn'); } catch (_) {}
          return;
        }
      }
    } catch (_) {}
  }
  try {
    const inv = getTauriInvoke();
    try { debugLog({ event: 'unlock.start' }); } catch (_) {}
    const text = await inv('unlock', { password: pwd });
    try { debugLog({ event: 'unlock.ok' }); } catch (_) {}
    const data = JSON.parse(typeof text === 'string' ? text : '[]');
    state.accounts = Array.isArray(data) ? data : [];
    hideLockOverlay();
    try { hideNotice(); } catch (_) {}
    renderAccounts();
    updateFileStatus();
    try { debugLog({ event: 'unlock.rendered', count: state.accounts.length }); } catch (_) {}
  } catch (e) {
    const msg = (e && e.message) ? e.message : (typeof e === 'string' ? e : (e && e.toString ? e.toString() : 'unknown error'));
    try { console.error('unlock failed (overlay path):', e); } catch (_) {}
    try { debugLog({ event: 'unlock.error', path: 'overlay', msg }, 'error'); } catch (_) {}
    try { showNotice(d.unlock_error + (msg ? (': ' + msg) : '')); } catch (_) {}
  }
});

async function bindJsonFile() {
  try {
    const inv = getTauriInvoke();
    if (inv) {
      // Tauri 模式：直接使用应用数据目录读取账户
      try {
        const text = await inv('read_accounts');
        const data = JSON.parse(typeof text === 'string' ? text : '[]');
        state.accounts = Array.isArray(data) ? data : [];
      } catch (_) { state.accounts = []; }
      updateFileStatus();
      saveToStorage();
      renderAccounts();
      return;
    }
    if (tauriProcess) {
      // 旧 Tauri sidecar 模式
      const data = await loadFromBridge();
      state.accounts = Array.isArray(data) ? data : [];
      updateFileStatus();
      saveToStorage();
      renderAccounts();
      return;
    }
    if (bridge) {
      const p = await bridge.choose_data_file();
      if (p) {
        state.boundPath = p;
        const data = await loadFromBridge();
        state.accounts = Array.isArray(data) ? data : [];
        updateFileStatus();
        saveToStorage();
        renderAccounts();
      }
      return;
    }
    if (!window.showOpenFilePicker) {
      alert('当前浏览器不支持文件访问 API，请使用 Chrome/Edge 最新版本');
      return;
    }
    const [handle] = await window.showOpenFilePicker({
      multiple: false,
      types: [{ description: 'JSON 文件', accept: { 'application/json': ['.json'] } }]
    });
    const file = await handle.getFile();
    const text = await file.text();
    let data = [];
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = [];
    }
    if (!Array.isArray(data)) data = [];
    state.accounts = data;
    state.fileHandle = handle;
    updateFileStatus();
    saveToStorage();
    await persistFileHandle(handle);
    renderAccounts();
  } catch (e) {
    if (e && e.name === 'AbortError') return;
    alert('绑定文件失败：' + (e && e.message ? e.message : e));
  }
}

async function newJsonFile() {
  try {
    const inv = getTauriInvoke();
    if (inv) {
      // Tauri 模式：直接使用应用数据目录，若不存在会创建空文件
      try {
        const text = await inv('read_accounts');
        const data = JSON.parse(typeof text === 'string' ? text : '[]');
        state.accounts = Array.isArray(data) ? data : [];
      } catch (_) { state.accounts = []; }
      updateFileStatus();
      saveToStorage();
      renderAccounts();
      return;
    }
    if (tauriProcess) {
      // 旧 Tauri sidecar 模式：读取或创建
      const data = await loadFromBridge();
      state.accounts = Array.isArray(data) ? data : [];
      updateFileStatus();
      saveToStorage();
      renderAccounts();
      return;
    }
    if (bridge) {
      // Python 端不区分新建/选择：如果不存在会创建空文件
      const p = await bridge.choose_data_file();
      if (p) {
        state.boundPath = p;
        updateFileStatus();
        const data = await loadFromBridge();
        state.accounts = Array.isArray(data) ? data : [];
        saveToStorage();
        renderAccounts();
      }
      return;
    }
    if (!window.showSaveFilePicker) {
      alert('当前浏览器不支持文件访问 API，请使用 Chrome/Edge 最新版本');
      return;
    }
    const handle = await window.showSaveFilePicker({
      suggestedName: '2fa-accounts.json',
      types: [{ description: 'JSON 文件', accept: { 'application/json': ['.json'] } }]
    });
    // 写入初始内容
    const writable = await handle.createWritable();
    await writable.write(JSON.stringify(state.accounts ?? [], null, 2));
    await writable.close();
    state.fileHandle = handle;
    updateFileStatus();
    await persistFileHandle(handle);
    // 同步到本地存储，保证刷新后快速显示
    saveToStorage();
  } catch (e) {
    if (e && e.name === 'AbortError') return; // 用户取消
    alert('新建数据文件失败：' + (e && e.message ? e.message : e));
  }
}

// 使用 IndexedDB 持久化文件句柄
function openHandleDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('fs-handles', 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('handles')) db.createObjectStore('handles');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function persistFileHandle(handle) {
  try {
    const db = await openHandleDB();
    const tx = db.transaction('handles', 'readwrite');
    tx.objectStore('handles').put(handle, 'bound');
    await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
    db.close();
  } catch (e) {
    console.warn('持久化文件句柄失败', e);
  }
}

async function restoreFileHandle() {
  try {
    const db = await openHandleDB();
    const tx = db.transaction('handles', 'readonly');
    const req = tx.objectStore('handles').get('bound');
    const handle = await new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
    db.close();
    if (!handle) return;
    const perm = await handle.queryPermission({ mode: 'readwrite' });
    if (perm === 'granted') {
      state.fileHandle = handle;
      updateFileStatus();
      // 从文件加载覆盖本地存储
      const file = await handle.getFile();
      const text = await file.text();
      const data = JSON.parse(text);
      if (Array.isArray(data)) {
        state.accounts = data;
        saveToStorage();
        renderAccounts();
      }
    } else {
      // 未授权，等待用户点击绑定按钮重新授权
      updateFileStatus();
    }
  } catch (e) {
    console.warn('恢复文件句柄失败', e);
  }
}

//（已撤回设置页功能）


function openDialog(editIndex = null) {
  state.editingIndex = editIndex;
  try { debugLog(`[openDialog] editIndex=${editIndex}`); } catch (_) {}
  const dict = getDict();
  if (editIndex != null) {
    const acc = state.accounts[editIndex];
    try { debugLog({ event: 'openDialog.edit', index: editIndex, acc }); } catch (_) {}
    if (dialogTitle) dialogTitle.setAttribute('data-i18n', 'dialog_title_edit');
    dialogTitle.textContent = dict.dialog_title_edit;
    labelInput.value = acc.label || '';
    issuerInput.value = acc.issuer || '';
    secretInput.value = acc.secret || '';
    digitsInput.value = acc.digits || 6;
    periodInput.value = acc.period || 30;
    if (algorithmInput) algorithmInput.value = (acc.algorithm || 'SHA1').toUpperCase();
    if (deleteAccountBtn) {
      deleteAccountBtn.style.display = 'inline-block';
      // 采用内置确认条，避免某些 WebView 下 confirm() 不可用
      deleteConfirmText && (deleteConfirmText.textContent = dict.confirm_delete || 'Delete this account?');
      deleteConfirmBar && (deleteConfirmBar.style.display = 'none');
      deleteAccountBtn.onclick = async () => {
        try { debugLog({ event: 'click.delete', index: editIndex }); } catch (_) {}
        if (deleteConfirmBar) deleteConfirmBar.style.display = 'flex';
        // 绑定一次性确认与取消
        if (confirmYesBtn) {
          confirmYesBtn.onclick = async () => {
            try { debugLog({ event: 'delete.inline.confirm', index: editIndex }); } catch (_) {}
            const deleted = await deleteAccount(editIndex, true);
            try { debugLog({ event: 'delete.result', index: editIndex, deleted }); } catch (_) {}
            if (deleteConfirmBar) deleteConfirmBar.style.display = 'none';
            if (deleted) accountDialog.close();
          };
        }
        if (confirmNoBtn) {
          confirmNoBtn.onclick = () => {
            try { debugLog({ event: 'delete.inline.cancel', index: editIndex }); } catch (_) {}
            if (deleteConfirmBar) deleteConfirmBar.style.display = 'none';
          };
        }
      };
    }
  } else {
    try { debugLog('[openDialog] add mode'); } catch (_) {}
    if (dialogTitle) dialogTitle.setAttribute('data-i18n', 'dialog_title_add');
    dialogTitle.textContent = dict.dialog_title_add;
    labelInput.value = '';
    issuerInput.value = '';
    secretInput.value = '';
    digitsInput.value = 6;
    periodInput.value = 30;
    if (algorithmInput) algorithmInput.value = 'SHA1';
    if (deleteAccountBtn) {
      deleteAccountBtn.style.display = 'none';
      deleteAccountBtn.onclick = null;
    }
    if (deleteConfirmBar) deleteConfirmBar.style.display = 'none';
  }
  accountDialog.showModal();
}

async function upsertAccount(evt) {
  // 若是取消按钮触发的提交，直接关闭弹窗并跳过保存逻辑
  const submitter = evt && evt.submitter ? evt.submitter : null;
  const isCancel = !!(submitter && submitter.value === 'cancel');
  if (isCancel) {
    evt.preventDefault();
    try { accountDialog.close(); } catch (_) { /* ignore */ }
    return;
  }
  // 保存流程：阻止默认提交，进入校验与保存
  evt.preventDefault();
  const dict = getDict();
  // 清除自定义校验提示
  try { labelInput.setCustomValidity(''); } catch (_) {}
  try { secretInput.setCustomValidity(''); } catch (_) {}
  // 运行内建校验（必填等），若不通过则显示浏览器校验提示
  if (!accountForm.checkValidity()) {
    accountForm.reportValidity();
    return;
  }
  const acc = {
    label: labelInput.value.trim(),
    issuer: issuerInput.value.trim(),
    secret: secretInput.value.trim(),
    digits: Number(digitsInput.value) || 6,
    period: Number(periodInput.value) || 30,
    algorithm: (algorithmInput && algorithmInput.value ? algorithmInput.value : 'SHA1'),
  };
  // 进一步校验密钥格式，不使用 alert，改为就地提示
  try { decodeSecret(acc.secret); } catch (e) {
    try {
      const msg = (dict.invalid_secret || 'Invalid secret') + (e && e.message ? `: ${e.message}` : '');
      secretInput.setCustomValidity(msg);
      secretInput.reportValidity();
    } catch (_) {}
    return;
  }
  const prev = state.accounts.slice();
  if (state.editingIndex != null) {
    state.accounts[state.editingIndex] = acc;
  } else {
    state.accounts.push(acc);
  }
  const ok = await persistAccounts();
  if (!ok) {
    // 写入失败（可能未解锁），回滚并保持弹窗开启以便用户重试或解锁
    state.accounts = prev;
    try { secretInput.setCustomValidity(''); } catch (_) {}
    try {
      const base = (dict.write_blocked || 'Write blocked: unlock and try again.');
      showNotice(lastError ? `${base} (${lastError})` : base);
    } catch (_) {}
    return;
  }
  accountDialog.close();
  renderAccounts();
  try { debugLog('[upsertAccount] saved and closed'); } catch (_) {}
}

async function deleteAccount(idx, skipConfirm = false) {
  try { debugLog({ event: 'deleteAccount.start', index: idx }); } catch (_) {}
  const dict = getDict();
  if (!skipConfirm) {
    const ok = confirm(dict.confirm_delete || 'Delete this account?');
    try { debugLog({ event: 'deleteAccount.confirm', index: idx, ok }); } catch (_) {}
    if (!ok) return false;
  }
  const prev = state.accounts.slice();
  const removed = state.accounts[idx];
  try { debugLog({ event: 'deleteAccount.splice.before', len: prev.length, removed }); } catch (_) {}
  state.accounts.splice(idx, 1);
  try { debugLog({ event: 'deleteAccount.splice.after', len: state.accounts.length }); } catch (_) {}
  const saved = await persistAccounts();
  try { debugLog({ event: 'deleteAccount.persist.done', saved, lastError }); } catch (_) {}
  if (!saved) {
    // 写入失败（可能未解锁），回滚并提示
    state.accounts = prev;
    try { debugLog({ event: 'deleteAccount.rollback', len: state.accounts.length }); } catch (_) {}
    renderAccounts();
    try {
      const base = (dict.write_blocked || 'Write blocked: unlock and try again.');
      showNotice(lastError ? `${base} (${lastError})` : base);
    } catch (_) {}
    return false;
  }
  renderAccounts();
  try { debugLog({ event: 'deleteAccount.success', len: state.accounts.length }); } catch (_) {}
  return true;
}

function renderAccounts() {
  accountsContainer.innerHTML = '';
  const tpl = document.getElementById('accountItemTpl');
  const dict = getDict();
  state.accounts.forEach((acc, idx) => {
    const node = tpl.content.cloneNode(true);
    node.querySelector('.name').textContent = acc.label || dict.unnamed;
    node.querySelector('.issuer').textContent = acc.issuer || '';
    const codeEl = node.querySelector('.code');
    const countdownEl = node.querySelector('.countdown');
    const progressEl = node.querySelector('.progress .bar');
    node.querySelector('.edit').addEventListener('click', () => { try { debugLog({ event: 'click.edit', index: idx }); } catch (_) {} openDialog(idx); });
    const qrBtn = node.querySelector('.qr');
    const qrImgEl = node.querySelector('.qr-img');
    const qrInfoEl = node.querySelector('.qr-info');

    // 双击复制当前验证码并显示 toast 提示
    if (codeEl) {
      codeEl.addEventListener('dblclick', async () => {
        const text = (codeEl.textContent || '').trim();
        if (!text) return;
        let ok = false;
        try {
          if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText(text);
            ok = true;
          }
        } catch (_) {}
        if (!ok) {
          try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            ok = !!document.execCommand && document.execCommand('copy');
            document.body.removeChild(ta);
          } catch (_) {}
        }
        try { if (ok) showNotice(dict.copy_success, 2000); } catch (_) {}
      });
    }

    // 自动生成并显示二维码，无需点击按钮
    (async () => {
      if (!qrImgEl || !qrInfoEl) return;
      const url = buildOtpauth(acc);
      qrInfoEl.textContent = dict.qr_generating;
      let b64 = '';
      let mime = 'image/png';
      // 优先使用 Tauri 原生命令生成二维码
      if (!b64) {
        const r = await generateQrViaTauri(url);
        if (r) { b64 = r.data; mime = r.mime; }
      }
      if (!b64) {
        const r = generateQrInBrowser(url);
        if (r) { b64 = r.data; mime = r.mime; }
      }
      if (!b64 && tauriProcess) {
        try {
          const res = await execSidecar(['qr', url]);
          if (res.code === 0) b64 = res.stdout || '';
        } catch (_) { /* ignore */ }
      } else if (bridge) {
        try {
          const r = await bridge.generate_qr(url);
          if (r) b64 = r;
        } catch (_) { /* ignore */ }
      }
      if (b64) {
        qrImgEl.src = `data:${mime};base64,${b64}`;
        qrImgEl.style.display = 'block';
        qrInfoEl.textContent = '';
      } else {
        qrImgEl.removeAttribute('src');
        qrImgEl.style.display = 'none';
        qrInfoEl.textContent = url + '\n' + dict.qr_no_dep;
      }
    })();
    qrBtn && qrBtn.addEventListener('click', async () => {
      if (!qrImgEl || !qrInfoEl) return;
      // 若已显示，则点击按钮收起
      const isVisible = (qrImgEl.style.display === 'block') || (qrInfoEl.textContent && qrInfoEl.textContent.trim() !== '');
      if (isVisible) {
        qrImgEl.removeAttribute('src');
        qrImgEl.style.display = 'none';
        qrInfoEl.textContent = '';
        return;
      }
      const url = buildOtpauth(acc);
      qrInfoEl.textContent = dict.qr_generating;
      let b64 = '';
      let mime = 'image/png';
      // 优先使用 Tauri 原生命令
      if (!b64) {
        const r = await generateQrViaTauri(url);
        if (r) { b64 = r.data; mime = r.mime; }
      }
      if (!b64) {
        const r = generateQrInBrowser(url);
        if (r) { b64 = r.data; mime = r.mime; }
      }
      if (!b64 && tauriProcess) {
        try {
          const res = await execSidecar(['qr', url]);
          if (res.code === 0) b64 = res.stdout || '';
        } catch (_) { /* ignore */ }
      } else if (bridge) {
        try {
          const r = await bridge.generate_qr(url);
          if (r) b64 = r;
        } catch (_) { /* ignore */ }
      }
      if (b64) {
        qrImgEl.src = `data:${mime};base64,${b64}`;
        qrImgEl.style.display = 'block';
        qrInfoEl.textContent = '';
      } else {
        qrImgEl.removeAttribute('src');
        qrImgEl.style.display = 'none';
        qrInfoEl.textContent = url + '\n' + dict.qr_no_dep;
      }
    });
    accountsContainer.appendChild(node);

    // 每秒更新一次该项目的 TOTP
    async function tick() {
      try {
        const { otp, remaining } = await totp({
          secretBase32: acc.secret,
          period: acc.period || 30,
          digits: acc.digits || 6,
          algorithm: (acc.algorithm || 'SHA1'),
        });
        codeEl.textContent = otp;
        countdownEl.textContent = `${dict.remaining} ${remaining}s`;
        if (progressEl) {
          const period = acc.period || 30;
          const pct = Math.max(0, Math.min(100, Math.round(((period - remaining) / period) * 100)));
          progressEl.style.width = pct + '%';
        }
      } catch (e) {
        codeEl.textContent = dict.invalid_secret;
        countdownEl.textContent = '';
        if (progressEl) progressEl.style.width = '0%';
      }
    }
    tick();
    const intervalId = setInterval(tick, 1000);
    // 清理：当重新渲染时移除间隔（简单做法：在下一次 render 重置容器即可）
  });
  // 渲染完列表后再应用一次国际化，覆盖动态节点文案
  applyI18n();
}

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < bytes.length; i++) {
    bits += bytes[i].toString(2).padStart(8, '0');
  }
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5);
    if (chunk.length < 5) {
      out += alphabet[parseInt(chunk.padEnd(5, '0'), 2)];
    } else {
      out += alphabet[parseInt(chunk, 2)];
    }
  }
  return out; // 不加 padding
}

function buildOtpauth(acc) {
  // secret 需要 Base32；若输入为 Hex/MD5，则转换为 Base32
  let secretParam = (acc.secret || '').trim();
  try {
    const bytes = decodeSecret(secretParam);
    secretParam = base32Encode(bytes);
  } catch (_) { /* 保持原值 */ }
  const issuer = encodeURIComponent(acc.issuer || '');
  const label = encodeURIComponent(`${acc.issuer ? acc.issuer + ':' : ''}${acc.label || '未命名'}`);
  const algorithm = (acc.algorithm || 'SHA1').toUpperCase();
  const digits = acc.digits || 6;
  const period = acc.period || 30;
  const params = new URLSearchParams({ secret: secretParam, issuer: acc.issuer || '', algorithm, digits: String(digits), period: String(period) });
  return `otpauth://totp/${label}?${params.toString()}`;
}

async function showQr(acc) {
  const dialog = document.getElementById('qrDialog');
  const img = document.getElementById('qrImg');
  const info = document.getElementById('qrInfo');
  const dict = getDict();
  const url = buildOtpauth(acc);
  info.textContent = url;
  let b64 = '';
  let mime = 'image/png';
  // 优先使用 Tauri 原生命令
  const r0 = await generateQrViaTauri(url);
  if (r0) { b64 = r0.data; mime = r0.mime; }
  if (!b64) {
    const r1 = generateQrInBrowser(url);
    if (r1) { b64 = r1.data; mime = r1.mime; }
  }
  if (b64) {
    // 若为 SVG，按主题色修饰颜色并透明化背景
    if (mime && /^image\/svg\+xml/.test(mime)) {
      try {
        const accent = (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#85b6ff').trim();
        const svgText = decodeURIComponent(escape(atob(b64)));
        const patched = svgText.replace(/fill="black"/g, `fill="${accent}"`)
                               .replace(/fill="white"/g, 'fill="none"');
        b64 = btoa(unescape(encodeURIComponent(patched)));
        mime = 'image/svg+xml';
      } catch (_) { /* ignore */ }
    }
    img.src = `data:${mime};base64,${b64}`;
    img.style.display = 'block';
  } else if (tauriProcess) {
    try {
      const res = await execSidecar(['qr', url]);
      const out = res.code === 0 ? (res.stdout || '') : '';
      if (out) {
        img.src = `data:image/png;base64,${out}`;
        img.style.display = 'block';
      } else {
        img.removeAttribute('src');
        img.style.display = 'none';
        info.textContent = url + '\n' + dict.qr_hint_desktop;
      }
    } catch (_) {
      img.removeAttribute('src');
      img.style.display = 'none';
      info.textContent = url + '\n' + dict.qr_hint_desktop;
    }
  } else if (bridge) {
    try {
      const b64 = await bridge.generate_qr(url);
      if (b64) {
        img.src = `data:image/png;base64,${b64}`;
        img.style.display = 'block';
      } else {
        // 桥接存在但未安装 qrcode 依赖
        img.removeAttribute('src');
        img.style.display = 'none';
        info.textContent = url + '\n' + dict.qr_hint_desktop;
      }
    } catch (_) {
      img.removeAttribute('src');
      img.style.display = 'none';
      info.textContent = url + '\n' + dict.qr_hint_desktop;
    }
  } else {
    // 纯浏览器环境：不使用外网回退，避免被阻止
    img.removeAttribute('src');
    img.style.display = 'none';
    info.textContent = url + '\n' + dict.qr_hint_browser;
  }
  dialog.showModal();
}

// 绑定二维码弹窗的关闭与遮罩点击关闭
(function bindQrDialogClose() {
  const dialog = document.getElementById('qrDialog');
  if (!dialog) return;
  const closeBtn = dialog.querySelector('.dialog-actions button');
  const img = document.getElementById('qrImg');
  const info = document.getElementById('qrInfo');
  function resetQr() {
    if (img) {
      img.removeAttribute('src');
      img.style.display = 'none';
    }
    if (info) info.textContent = '';
  }
  closeBtn && closeBtn.addEventListener('click', () => {
    dialog.close();
    resetQr();
  });
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) {
      dialog.close();
      resetQr();
    }
  });
  dialog.addEventListener('cancel', () => resetQr());
})();

function parseOtpauthUrl(input) {
  const val = (input || '').trim();
  const re = /^otpauth:\/\/totp\//i;
  if (!re.test(val)) throw new Error('不是 TOTP otpauth URL');
  const url = new URL(val);
  const rawLabel = decodeURIComponent(url.pathname.slice(1));
  let label = rawLabel;
  let issuer = url.searchParams.get('issuer') || '';
  if (rawLabel.includes(':')) {
    const [iss, lab] = rawLabel.split(':');
    if (!issuer) issuer = iss;
    label = lab;
  }
  const secret = url.searchParams.get('secret') || '';
  const digits = Number(url.searchParams.get('digits') || 6);
  const period = Number(url.searchParams.get('period') || 30);
  const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  return { label, issuer, secret, digits, period, algorithm };
}

importOtpauthBtn && importOtpauthBtn.addEventListener('click', () => {
  const input = prompt('粘贴 otpauth URL');
  if (!input) return;
  try {
    const data = parseOtpauthUrl(input);
    labelInput.value = data.label || '';
    issuerInput.value = data.issuer || '';
    secretInput.value = data.secret || '';
    digitsInput.value = data.digits || 6;
    periodInput.value = data.period || 30;
    if (algorithmInput) algorithmInput.value = data.algorithm || 'SHA1';
  } catch (e) {
    alert(e.message || e);
  }
});

// 已移除导入/导出功能

addAccountBtn.addEventListener('click', () => openDialog());
accountForm.addEventListener('submit', upsertAccount);

// 重置到首次运行：清空本地状态与持久化，并触发设置主密码流程
resetBtn && resetBtn.addEventListener('click', async () => {
  const d = getDict();
  try { debugLog({ event: 'reset.start' }); } catch (_) {}
  // 桌面环境：调用原生命令清理数据与配置
  if (getTauriInvoke()) {
    try {
      const inv = getTauriInvoke();
      await inv('reset_all');
      try { debugLog('reset.tauri.ok'); } catch (_) {}
      // 尝试写入空账户作为冗余保障
      try {
        await inv('write_accounts', { data: JSON.stringify([]) });
        try { debugLog('reset.write_empty.ok'); } catch (_) {}
      } catch (e) {
        try { debugLog({ event: 'reset.write_empty.err', err: (e && e.message) ? e.message : e }, 'warn'); } catch (_) {}
      }
    } catch (e) {
      try { debugLog({ event: 'reset.tauri.err', err: (e && e.message) ? e.message : e }, 'error'); } catch (_) {}
    }
  }
  // 浏览器本地缓存：清理账号与配置
  try {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(CONFIG_KEY);
    // 预览模式跳过标记也一并清理
    localStorage.removeItem(PREVIEW_SETUP_DONE_KEY);
    // 预览模式主密码哈希一并清理
    localStorage.removeItem(PREVIEW_MASTER_HASH_KEY);
  } catch (_) {}
  // 清空内存状态，保留当前语言设置
  const lang = (state?.config?.language) || (langSelect ? langSelect.value : 'en');
  state.accounts = [];
  state.editingIndex = null;
  state.fileHandle = null;
  state.boundPath = null;
  state.config = { accent: '#85b6ff', language: lang };
  lastError = null;
  try { hideLockOverlay(); } catch (_) {}
  try { renderAccounts(); } catch (_) {}
  try { applyI18n(); } catch (_) {}
  try { updateFileStatus(); } catch (_) {}
  try { showNotice(d.title === '本地 2FA 管家' ? '已重置到首次运行。' : 'Reset to first run.'); } catch (_) {}
  try { debugLog('reset.done'); } catch (_) {}
  // 立即触发设置主密码弹窗
  try {
    if (getTauriInvoke()) {
      const inv = getTauriInvoke();
      const enc = await inv('is_encrypted');
      if (enc) {
        // 若仍处于加密状态，则要求解锁，而非重复设置
        showLockOverlay();
      } else {
        showSetMasterDialog();
      }
    } else {
      // 浏览器环境：强制显示设置主密码遮罩（模拟）
      showSetMasterDialog({ force: true });
    }
  } catch (_) {}
});

// 初始化：优先通过 Python 桥接加载
(async () => {
  // 先加载配置并应用主题色等设置
  await loadConfig();
  applyI18n();
  await logCurrentTitle('init');
  // 检测桌面/本地开发上下文：Tauri 或本机端口（localhost/127.0.0.1）
  const isDesktopLike = !!window.__TAURI__ || (function () {
    try {
      const o = String(location.origin || '');
      return /^http:\/\/(localhost|127\.0\.0\.1):\d+/.test(o);
    } catch (_) { return false; }
  })();
  try {
    debugLog({
      event: 'env.detect',
      tauri: !!getTauriInvoke(),
      pywebview: !!bridge,
      hasFileHandle: !!state.fileHandle,
      desktopLike: !!isDesktopLike
    });
  } catch (_) {}
  try { updateEnvBadge(); } catch (_) {}
  try { logTauriStatus('init'); } catch (_) {}
  // 强制重置：当 URL 带 ?forceReset=1 时，无条件执行后直接进入“设置主密码”
  try {
    const inv = getTauriInvoke();
    const urlForce = (() => { try { return new URLSearchParams(location.search).get('forceReset') === '1'; } catch (_) { return false; } })();
    const onceFlag = (() => { try { return localStorage.getItem('__force_reset_once'); } catch (_) { return null; } })();
    if (inv && (urlForce || !onceFlag)) {
      try { debugLog({ event: 'forceReset.trigger', urlForce, onceFlag }); } catch (_) {}
      await inv('reset_all');
      // 写入空数组，确保 data.json 处于未加密的明文初始状态
      try { await inv('write_accounts', { data: JSON.stringify([]) }); } catch (_) {}
      // 清理预览标记，避免逻辑分支误判
      try {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(CONFIG_KEY);
        localStorage.removeItem(PREVIEW_SETUP_DONE_KEY);
        localStorage.removeItem(PREVIEW_MASTER_HASH_KEY);
      } catch (_) {}
      try { localStorage.setItem('__force_reset_once', 'done'); } catch (_) {}
      // 直接进入首次设置流程（不依赖后续 is_encrypted 判断）
      try {
        document.body.classList.add('locked');
        if (setupOverlay) setupOverlay.classList.add('show');
        showSetMasterDialog();
      } catch (_) {}
      return;
    }
  } catch (_) {}
  // 在桌面类环境中，优先显示“首次设置”遮罩以阻止直接进入主界面
  try {
    if (isDesktopLike) {
      const previewSetupDone = (() => { try { return !!localStorage.getItem(PREVIEW_SETUP_DONE_KEY); } catch (_) { return false; } })();
      // Tauri 已注入：根据加密状态决定显示“设置”或“解锁”
      if (getTauriInvoke()) {
        document.body.classList.add('locked');
        const inv = getTauriInvoke();
        try {
          const enc = await inv('is_encrypted');
          if (enc) {
            // 已加密：仅显示解锁遮罩，避免误显首次设置
            if (setupOverlay) setupOverlay.classList.remove('show');
            showLockOverlay();
          } else {
            // 未加密：显示首次设置遮罩并进入设置流程
            if (setupOverlay) setupOverlay.classList.add('show');
            showSetMasterDialog();
          }
        } catch (_) {
          // 保守处理：若判断失败则进入解锁遮罩，避免直接暴露内容
          if (setupOverlay) setupOverlay.classList.remove('show');
          showLockOverlay();
        }
      } else if (!previewSetupDone) {
        // 未注入且未完成预览标记：展示遮罩及备用设置
        document.body.classList.add('locked');
        if (setupOverlay) setupOverlay.classList.add('show');
        try {
          if (setupPwdRow) setupPwdRow.style.display = '';
          if (setupConfirmRow) setupConfirmRow.style.display = '';
          if (setupSubmitBtn) setupSubmitBtn.style.display = '';
          if (setupPwdInput) setTimeout(() => { try { setupPwdInput.focus(); } catch (_) {} }, 0);
          bindSetupFallbackSubmit();
        } catch (_) {}
      } else {
        // 未注入但预览已完成：若已有主密码哈希，则直接进入解锁流程；否则继续显示首次设置
        const hasHash = (() => { try { return !!localStorage.getItem(PREVIEW_MASTER_HASH_KEY); } catch (_) { return false; } })();
        if (hasHash) {
          document.body.classList.add('locked');
          if (setupOverlay) setupOverlay.classList.remove('show');
          showLockOverlay();
        } else {
          document.body.classList.add('locked');
          if (setupOverlay) setupOverlay.classList.add('show');
          try {
            if (setupPwdRow) setupPwdRow.style.display = '';
            if (setupConfirmRow) setupConfirmRow.style.display = '';
            if (setupSubmitBtn) setupSubmitBtn.style.display = '';
            if (setupPwdInput) setTimeout(() => { try { setupPwdInput.focus(); } catch (_) {} }, 0);
            bindSetupFallbackSubmit();
          } catch (_) {}
        }
      }
    }
  } catch (_) {}
  // 保险：无论是否检测到原生 API，也绑定一次备用提交逻辑（幂等）
  try { bindSetupFallbackSubmit(); } catch (_) {}
  // 若 Tauri 注入在 dev 模式下有延迟，这里轮询等待并在可用后补做初始化与系统标题同步
  (async function waitTauriAndInit() {
    if (getTauriInvoke()) return;
    for (let i = 0; i < 300; i++) { // 最长约 15s
      await new Promise(r => setTimeout(r, 50));
      const inv = getTauriInvoke();
      if (inv) {
        try { debugLog({ event: 'tauri.injected' }); } catch (_) {}
        try { logTauriStatus('after.injected'); } catch (_) {}
        try { updateEnvBadge(); } catch (_) {}
        // 注入后同步一次系统窗体标题
        try { applyI18n(); } catch (_) {}
        try { await logCurrentTitle('tauri.injected.afterTitleSync'); } catch (_) {}
        // 若尚未加载且未处于锁定流程，补做桌面初始化逻辑（加密判断与数据读取）
        try {
          if (!loaded && !needUnlock) {
            const enc = await inv('is_encrypted');
            if (enc) {
              needUnlock = true;
              try { if (setupOverlay) setupOverlay.classList.remove('show'); } catch (_) {}
              showLockOverlay();
            } else {
              const text = await inv('read_accounts');
              const data = JSON.parse(typeof text === 'string' ? text : '[]');
              if (Array.isArray(data)) {
                state.accounts = data;
                loaded = true;
                renderAccounts();
                // 未加密：强制设置主密码
                showSetMasterDialog();
              }
            }
            updateFileStatus();
          }
        } catch (_) { /* ignore */ }
        break;
      }
    }
    // 若超过等待窗口仍未注入，记录一次超时日志并刷新徽章
    if (!getTauriInvoke()) {
      try { debugLog({ event: 'tauri.injected.timeout' }); } catch (_) {}
      try { logTauriStatus('after.timeout'); } catch (_) {}
      try { updateEnvBadge(); } catch (_) {}
    }
  })();
  // 在桌面主进程环境下，避免浏览器本地缓存的账号干扰首次体验
  try { if (getTauriInvoke()) localStorage.removeItem(STORAGE_KEY); } catch (_) { /* ignore */ }
  setupFormValidationI18n();
  setupLangSelectUI();
  // 应用环境徽章与构建标记
  try { updateEnvBadge(); } catch (_) {}
  try { applyBuildMarker(); } catch (_) {}
  let loaded = false;
  let needUnlock = false;
  // 浏览器模拟模式：通过 URL 参数 simulate=lock/encrypted/setup 强制流程
  try {
    let sim = null;
    try { sim = new URLSearchParams(location.search).get('simulate'); } catch (_) {}
    if (!getTauriInvoke() && sim) {
      try { debugLog({ event: 'dev.sim', mode: sim }); } catch (_) {}
      if (sim === 'lock' || sim === 'encrypted') {
        needUnlock = true;
        showLockOverlay();
      } else if (sim === 'setup') {
        showSetMasterDialog({ force: true });
      }
    }
  } catch (_) { /* ignore */ }
  // 首次未加密时，强制设置主密码（不论是否已有数据）
  {
    const invInit = getTauriInvoke();
    if (invInit) {
    try {
      const enc = await invInit('is_encrypted');
      if (enc) {
        // 已启用加密：启动即要求解锁，不尝试读取数据
        needUnlock = true;
        showLockOverlay();
      } else {
        const text = await invInit('read_accounts');
        const data = JSON.parse(typeof text === 'string' ? text : '[]');
        if (Array.isArray(data)) {
          state.accounts = data;
          loaded = true;
          // 未加密：强制设置主密码
          showSetMasterDialog();
        }
      }
    } catch (_) { /* ignore */ }
    }
  }
  if (bridge && !needUnlock) {
    const data = await loadFromBridge();
    if (Array.isArray(data)) {
      state.accounts = data;
      loaded = true;
    }
  }
  // 桌面类环境下，避免直接以浏览器缓存渲染主界面（等待注入/加密判断）
  if (!loaded && !needUnlock && !isDesktopLike) {
    loadFromStorage();
    renderAccounts();
    restoreFileHandle();
  } else if (loaded) {
    renderAccounts();
  }
  updateFileStatus();
  // 统一首次体验：未加密则弹出“设置主密码”。
  try {
    const invCheck = getTauriInvoke();
    const enc = invCheck ? await invCheck('is_encrypted') : false;
    if (getTauriInvoke() && !needUnlock && !enc) {
      showSetMasterDialog();
    }
  } catch (_) { /* ignore */ }
  // 绑定启用主密码按钮（浏览器也可触发模拟遮罩）
  if (enableMasterBtn) {
    enableMasterBtn.addEventListener('click', async () => {
      try { debugLog({ event: 'enableMasterBtn.click' }); } catch (_) {}
      try {
        if (getTauriInvoke()) {
          try { debugLog({ event: 'enableMasterBtn.path', mode: 'tauri' }); } catch (_) {}
          const invBtn = getTauriInvoke();
          const enc = await invBtn('is_encrypted');
          if (enc) {
            alert('当前已启用主密码');
            return;
          }
          showSetMasterDialog();
        } else {
          try { debugLog({ event: 'enableMasterBtn.path', mode: 'browser' }); } catch (_) {}
          // 浏览器环境：直接显示模拟遮罩
          showSetMasterDialog({ force: true });
        }
      } catch (_) { /* ignore */ }
    });
  }
})();