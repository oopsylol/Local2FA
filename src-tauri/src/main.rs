#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tauri::{Manager, State};
use std::sync::Mutex;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use std::sync::mpsc::channel;
use std::thread;

use rand::RngCore;
use chacha20poly1305::{aead::Aead, aead::KeyInit, ChaCha20Poly1305, Key, Nonce};
use argon2::{Argon2, Algorithm, Params, Version};
use base64::{engine::general_purpose, Engine as _};

#[tauri::command]
fn generate_qr(url: String) -> Result<String, String> {
    use base64::Engine;
    use qrcode::render::svg;
    use qrcode::QrCode;

    let code = QrCode::new(url.as_bytes()).map_err(|e| e.to_string())?;
    let svg = code
        .render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000"))
        .light_color(svg::Color("#fff"))
        .build();

    let b64 = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
    Ok(b64)
}

fn app_data_dir(_app_handle: &tauri::AppHandle) -> PathBuf {
    // 简化：macOS 环境下使用 ~/Library/Application Support/Local2FA
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Local2FA")
}

fn config_path(app_handle: &tauri::AppHandle) -> PathBuf { app_data_dir(app_handle).join("config.json") }

fn data_path_from_config(app_handle: &tauri::AppHandle) -> PathBuf {
    let default_dir = app_data_dir(app_handle);
    let cfg_p = config_path(app_handle);
    if let Ok(text) = fs::read_to_string(&cfg_p) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(dir) = v.get("data_dir").and_then(|s| s.as_str()) {
                let p = PathBuf::from(dir);
                if p.is_dir() { return p; }
            }
        }
    }
    default_dir
}

fn data_file_path(app_handle: &tauri::AppHandle) -> PathBuf { data_path_from_config(app_handle).join("data.json") }

#[derive(Default)]
struct AppState {
    key: Option<[u8; 32]>,
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let params = Params::new(19 * 1024, 2, 1, None).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    a2.hash_password_into(password.as_bytes(), salt, &mut out).expect("argon2 derive");
    out
}

// 从加密文件的参数派生密钥，兼容不同 Argon2 配置
fn derive_key_with_params(password: &str, salt: &[u8], params_obj: Option<&serde_json::Value>) -> [u8; 32] {
    let mut out = [0u8; 32];
    // 默认参数与当前实现一致
    let mut m_cost: u32 = 19 * 1024;
    let mut t_cost: u32 = 2;
    let mut p_cost: u32 = 1;
    if let Some(pv) = params_obj.and_then(|v| v.as_object()) {
        if let Some(mv) = pv.get("m").and_then(|x| x.as_u64()) { m_cost = mv.min(u64::from(u32::MAX)) as u32; }
        if let Some(tv) = pv.get("t").and_then(|x| x.as_u64()) { t_cost = tv.min(u64::from(u32::MAX)) as u32; }
        if let Some(pv2) = pv.get("p").and_then(|x| x.as_u64()) { p_cost = pv2.min(u64::from(u32::MAX)) as u32; }
    }
    let params = Params::new(m_cost, t_cost, p_cost, None).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    a2.hash_password_into(password.as_bytes(), salt, &mut out).expect("argon2 derive");
    out
}

fn encrypt_json(key_bytes: &[u8; 32], plaintext: &str) -> serde_json::Value {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("encryption success");
    json!({
        "enc": "v1",
        "aead": "chacha20poly1305",
        "kdf": "argon2id",
        "params": {"m": 19456, "t": 2, "p": 1},
        "salt": general_purpose::STANDARD.encode(salt),
        "nonce": general_purpose::STANDARD.encode(nonce_bytes),
        "ciphertext": general_purpose::STANDARD.encode(ct)
    })
}

fn try_decrypt_json(key_bytes: &[u8; 32], wrapper: &serde_json::Value) -> Result<String, String> {
    let _salt_b64 = wrapper.get("salt").and_then(|v| v.as_str()).ok_or("missing salt")?;
    let nonce_b64 = wrapper.get("nonce").and_then(|v| v.as_str()).ok_or("missing nonce")?;
    let ct_b64 = wrapper.get("ciphertext").and_then(|v| v.as_str()).ok_or("missing ciphertext")?;
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).map_err(|e| e.to_string())?;
    let ct = general_purpose::STANDARD.decode(ct_b64).map_err(|e| e.to_string())?;
    if nonce_bytes.len() != 12 { return Err("invalid nonce".into()); }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher.decrypt(nonce, ct.as_ref()).map_err(|_| "decrypt failed")?;
    String::from_utf8(pt).map_err(|e| e.to_string())
}

fn file_is_encrypted(path: &PathBuf) -> bool {
    if let Ok(text) = fs::read_to_string(path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return v.get("enc").and_then(|x| x.as_str()) == Some("v1");
        }
    }
    false
}

#[tauri::command]
fn get_data_dir(app_handle: tauri::AppHandle) -> Result<String, String> {
    let dir = data_path_from_config(&app_handle);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.to_string_lossy().to_string())
}

#[tauri::command]
fn read_config(app_handle: tauri::AppHandle) -> Result<String, String> {
    let p = config_path(&app_handle);
    if !p.exists() { return Ok("{}".into()); }
    fs::read_to_string(p).map_err(|e| e.to_string())
}

#[tauri::command]
fn write_config(app_handle: tauri::AppHandle, data: String) -> Result<(), String> {
    let p = config_path(&app_handle);
    fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&p, &data).map_err(|e| e.to_string())?;
    // 根据语言更新窗体标题（动态），避免前端注入不可用时标题不同步
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
        let lang = v.get("language").and_then(|x| x.as_str()).unwrap_or("en");
        let title = if lang == "zh" { "本地 2FA 管家" } else { "Local 2FA Manager" };
        if let Some(win) = app_handle.get_webview_window("main") {
            let _ = win.set_title(title);
        }
    }
    Ok(())
}

#[tauri::command]
fn set_data_dir(app_handle: tauri::AppHandle, path: String) -> Result<(), String> {
    let mut v = serde_json::Value::Object(serde_json::Map::new());
    if let Ok(text) = fs::read_to_string(config_path(&app_handle)) {
        if let Ok(old) = serde_json::from_str::<serde_json::Value>(&text) { v = old; }
    }
    let dir = PathBuf::from(path);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    v.as_object_mut().unwrap().insert("data_dir".into(), json!(dir.to_string_lossy().to_string()));
    let s = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    fs::write(config_path(&app_handle), s).map_err(|e| e.to_string())
}

#[tauri::command]
fn is_encrypted(app_handle: tauri::AppHandle) -> Result<bool, String> {
    let p = data_file_path(&app_handle);
    Ok(file_is_encrypted(&p))
}

#[tauri::command]
fn is_locked(state: State<Mutex<AppState>>) -> Result<bool, String> {
    Ok(state.lock().unwrap().key.is_none())
}

#[tauri::command]
fn lock(state: State<Mutex<AppState>>) -> Result<(), String> {
    // 清空内存中的密钥以模拟锁定状态，不修改任何文件
    state.lock().unwrap().key.take();
    Ok(())
}

#[tauri::command]
fn set_master_password(app_handle: tauri::AppHandle, state: State<Mutex<AppState>>, password: String) -> Result<(), String> {
    let p = data_file_path(&app_handle);
    // 读取现有内容
    let current = if p.exists() { fs::read_to_string(&p).map_err(|e| e.to_string())? } else { "[]".into() };
    // 若已加密则拒绝重复设置
    if file_is_encrypted(&p) { return Err("already encrypted".into()); }
    // 生成盐并派生密钥
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(&password, &salt);
    // 使用派生出的密钥加密（encrypt_json 内部会重新生成盐与 nonce），这里用我们生成的盐以确定性派生
    let wrapper = {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, current.as_bytes()).map_err(|e| e.to_string())?;
        json!({
            "enc": "v1",
            "aead": "chacha20poly1305",
            "kdf": "argon2id",
            "params": {"m": 19456, "t": 2, "p": 1},
            "salt": general_purpose::STANDARD.encode(salt),
            "nonce": general_purpose::STANDARD.encode(nonce_bytes),
            "ciphertext": general_purpose::STANDARD.encode(ct)
        })
    };
    fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&p, serde_json::to_string(&wrapper).unwrap()).map_err(|e| e.to_string())?;
    // 将密钥保存到内存状态
    state.lock().unwrap().key.replace(key);
    Ok(())
}

#[tauri::command]
fn unlock(app_handle: tauri::AppHandle, state: State<Mutex<AppState>>, password: String) -> Result<String, String> {
    let p = data_file_path(&app_handle);
    let text = fs::read_to_string(&p).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if v.get("enc").and_then(|x| x.as_str()) != Some("v1") {
        return Err("not encrypted".into());
    }
    let salt_b64 = v.get("salt").and_then(|s| s.as_str()).ok_or("missing salt")?;
    let salt = general_purpose::STANDARD.decode(salt_b64).map_err(|e| e.to_string())?;
    // 读取加密文件中的 Argon2 参数以确保派生一致
    let params_obj = v.get("params");
    let key = derive_key_with_params(&password, &salt, params_obj);
    let pt = try_decrypt_json(&key, &v)?;
    state.lock().unwrap().key.replace(key);
    Ok(pt)
}

#[tauri::command]
fn read_accounts(app_handle: tauri::AppHandle, state: State<Mutex<AppState>>) -> Result<String, String> {
    let p = data_file_path(&app_handle);
    if !p.exists() { fs::write(&p, "[]").map_err(|e| e.to_string())?; }
    let text = fs::read_to_string(&p).map_err(|e| e.to_string())?;
    if file_is_encrypted(&p) {
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let guard = state.lock().unwrap();
        let key = guard.key.as_ref().ok_or("locked")?;
        let pt = try_decrypt_json(key, &v)?;
        Ok(pt)
    } else {
        Ok(text)
    }
}

#[tauri::command]
fn write_accounts(app_handle: tauri::AppHandle, state: State<Mutex<AppState>>, data: String) -> Result<(), String> {
    let p = data_file_path(&app_handle);
    fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    if file_is_encrypted(&p) {
        let guard = state.lock().unwrap();
        let key = guard.key.as_ref().ok_or("locked")?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, data.as_bytes()).map_err(|e| e.to_string())?;
        // 保持原来的盐用于派生
        let old = fs::read_to_string(&p).unwrap_or_else(|_| "{}".into());
        let old_v: serde_json::Value = serde_json::from_str(&old).unwrap_or(json!({}));
        let salt_b64 = old_v.get("salt").and_then(|s| s.as_str()).unwrap_or("");
        let wrapper = json!({
            "enc": "v1",
            "aead": "chacha20poly1305",
            "kdf": "argon2id",
            "params": {"m": 19456, "t": 2, "p": 1},
            "salt": salt_b64,
            "nonce": general_purpose::STANDARD.encode(nonce_bytes),
            "ciphertext": general_purpose::STANDARD.encode(ct)
        });
        fs::write(&p, serde_json::to_string(&wrapper).unwrap()).map_err(|e| e.to_string())?
    } else {
        // 若未加密，直接写入明文
        fs::write(&p, data).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn reset_all(app_handle: tauri::AppHandle, state: State<Mutex<AppState>>) -> Result<(), String> {
    let cfg = config_path(&app_handle);
    let data = data_file_path(&app_handle);
    if cfg.exists() {
        fs::remove_file(&cfg).map_err(|e| e.to_string())?;
    }
    if data.exists() {
        fs::remove_file(&data).map_err(|e| e.to_string())?;
    }
    // 清空内存中的密钥状态
    state.lock().unwrap().key.take();
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(AppState::default()))
        .setup(|app| {
            // 根据配置语言初始化窗体标题，避免前端注入未就绪导致标题不一致
            let handle = app.handle();
            let mut title = "Local 2FA Manager".to_string();
            let cfg_p = config_path(&handle);
            if let Ok(text) = fs::read_to_string(&cfg_p) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let lang = v.get("language").and_then(|x| x.as_str()).unwrap_or("en");
                    if lang == "zh" { title = "本地 2FA 管家".to_string(); }
                }
            }
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.set_title(&title);
            }

            // 监听配置文件变更，动态同步窗口标题（即便前端注入不可用，也能生效）
            {
                let handle2 = handle.clone();
                let cfg_watch_path = cfg_p.clone();
                thread::spawn(move || {
                    let (tx, rx) = channel();
                    let mut watcher = RecommendedWatcher::new(move |res| {
                        let _ = tx.send(res);
                    }, notify::Config::default()).expect("watcher");
                    // 监听配置所在目录，过滤目标文件
                    let _ = watcher.watch(cfg_watch_path.parent().unwrap_or_else(|| std::path::Path::new(".")), RecursiveMode::NonRecursive);
                    // 循环处理事件
                    while let Ok(res) = rx.recv() {
                        if let Ok(event) = res {
                            // 只处理修改/创建事件
                            match event.kind {
                                EventKind::Modify(_) | EventKind::Create(_) => {
                                    // 若事件涉及到我们的配置文件则读取并更新标题
                                    let hit = event.paths.iter().any(|p| p == &cfg_watch_path);
                                    if hit {
                                        if let Ok(text) = fs::read_to_string(&cfg_watch_path) {
                                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                                                let lang = v.get("language").and_then(|x| x.as_str()).unwrap_or("en");
                                                let new_title = if lang == "zh" { "本地 2FA 管家" } else { "Local 2FA Manager" };
                                                if let Some(win) = handle2.get_webview_window("main") {
                                                    let _ = win.set_title(new_title);
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            generate_qr,
            get_data_dir,
            read_config,
            write_config,
            set_data_dir,
            is_encrypted,
            is_locked,
            lock,
            set_master_password,
            unlock,
            read_accounts,
            write_accounts,
            reset_all,
            set_title,
            get_title,
            emit_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn set_title(app_handle: tauri::AppHandle, title: String) -> Result<(), String> {
    if let Some(win) = app_handle.get_webview_window("main") {
        win.set_title(&title).map_err(|e| e.to_string())
    } else {
        Err("window not found".into())
    }
}

#[tauri::command]
fn get_title(app_handle: tauri::AppHandle) -> Result<String, String> {
    // 尝试从配置推断当前标题（Tauri 暂无稳定的标题读取 API，使用配置语言作为来源）
    let cfg_p = config_path(&app_handle);
    let mut lang = String::from("en");
    if let Ok(text) = fs::read_to_string(&cfg_p) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            lang = v.get("language").and_then(|x| x.as_str()).unwrap_or("en").to_string();
        }
    }
    let title = if lang == "zh" { "本地 2FA 管家".to_string() } else { "Local 2FA Manager".to_string() };
    Ok(title)
}

#[tauri::command]
fn emit_log(level: String, message: String) -> Result<(), String> {
    // 将前端的日志输出到终端，便于在 Tauri 环境调试
    match level.as_str() {
        "error" => { eprintln!("[error] {}", message); },
        "warn" => { eprintln!("[warn] {}", message); },
        _ => { println!("[info] {}", message); },
    }
    Ok(())
}