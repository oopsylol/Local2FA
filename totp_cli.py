#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

APP_NAME = "Local2FA"
APP_DIR = Path.home() / "Library" / "Application Support" / APP_NAME
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / "accounts.json"


def decode_secret(secret: str) -> bytes:
    s = secret.strip().replace(" ", "")
    # Hex 检测（偶数长度）
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        return bytes.fromhex(s)
    # Base32（容忍无填充）
    s = s.upper()
    pad_len = (-len(s)) % 8
    s_padded = s + ("=" * pad_len)
    try:
        return base64.b32decode(s_padded, casefold=True)
    except Exception as e:
        raise ValueError(f"密钥格式错误：{e}")


def totp(secret_bytes: bytes, period: int = 30, digits: int = 6, timestamp: float = None) -> tuple[str, int]:
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp // period)
    remaining = period - (int(timestamp) % period)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code_int = ((h[o] & 0x7F) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]
    otp = code_int % (10 ** digits)
    return str(otp).zfill(digits), remaining


def load_accounts():
    if not DB_PATH.exists():
        return []
    try:
        return json.loads(DB_PATH.read_text("utf-8"))
    except Exception:
        return []


def save_accounts(accounts):
    DB_PATH.write_text(json.dumps(accounts, ensure_ascii=False, indent=2), "utf-8")


def print_codes(accounts):
    if not accounts:
        print("暂无账号。使用命令 `add` 添加一个账号。")
        return
    now = time.time()
    for acc in accounts:
        try:
            secret = decode_secret(acc.get("secret", ""))
            digits = int(acc.get("digits", 6))
            period = int(acc.get("period", 30))
            code, rem = totp(secret, period=period, digits=digits, timestamp=now)
            label = acc.get("label", "未命名")
            issuer = acc.get("issuer", "")
            name = f"{label}" + (f" ({issuer})" if issuer else "")
            print(f"{name}: {code}  剩余 {rem}s")
        except Exception as e:
            print(f"{acc.get('label','未命名')}: 密钥无效 - {e}")


def add_interactive(accounts):
    print("添加账号：")
    label = input("账号名称: ").strip()
    issuer = input("发行者/平台(可选): ").strip()
    secret = input("密钥(Base32 或 Hex/MD5): ").strip()
    digits = input("位数(默认6): ").strip() or "6"
    period = input("周期秒(默认30): ").strip() or "30"
    # 校验密钥格式
    try:
        decode_secret(secret)
    except Exception as e:
        print("密钥格式不正确:", e)
        return
    acc = {
        "label": label,
        "issuer": issuer,
        "secret": secret,
        "digits": int(digits),
        "period": int(period),
    }
    accounts.append(acc)
    save_accounts(accounts)
    print("已保存。")


def main():
    accounts = load_accounts()
    if len(sys.argv) == 1:
        # 默认打印当前所有账号的 TOTP
        print_codes(accounts)
        return
    cmd = sys.argv[1]
    if cmd == "add":
        add_interactive(accounts)
    elif cmd == "list":
        for i, a in enumerate(accounts):
            print(f"[{i}] {a.get('label','未命名')} - {a.get('issuer','')}")
    elif cmd == "del" and len(sys.argv) > 2:
        idx = int(sys.argv[2])
        if 0 <= idx < len(accounts):
            removed = accounts.pop(idx)
            save_accounts(accounts)
            print("已删除:", removed.get("label"))
        else:
            print("索引无效")
    else:
        print("用法: totp_cli.py [add|list|del <index>] ；空参数打印当前验证码")


if __name__ == "__main__":
    main()