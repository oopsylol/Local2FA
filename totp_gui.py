#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import time
import tkinter as tk
from tkinter import messagebox, simpledialog
from pathlib import Path

APP_NAME = "Local2FA"
APP_DIR = Path.home() / "Library" / "Application Support" / APP_NAME
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / "accounts.json"


def decode_secret(secret: str) -> bytes:
    s = secret.strip().replace(" ", "")
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        return bytes.fromhex(s)
    s = s.upper()
    pad_len = (-len(s)) % 8
    s_padded = s + ("=" * pad_len)
    return base64.b32decode(s_padded, casefold=True)


def totp(secret_bytes: bytes, period: int = 30, digits: int = 6) -> tuple[str, int]:
    now = time.time()
    counter = int(now // period)
    remaining = period - (int(now) % period)
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


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("本机 2FA 管理器 (Python)")
        self.accounts = load_accounts()

        top = tk.Frame(root)
        top.pack(fill=tk.X, padx=12, pady=8)
        tk.Button(top, text="添加账号", command=self.add_account).pack(side=tk.LEFT)
        tk.Button(top, text="删除选中", command=self.delete_selected).pack(side=tk.LEFT, padx=(8, 0))

        self.list = tk.Listbox(root, height=12)
        self.list.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        self.status = tk.Label(root, text="", anchor="w")
        self.status.pack(fill=tk.X, padx=12, pady=(0, 8))

        self.render()
        self.tick()

    def render(self):
        self.list.delete(0, tk.END)
        for acc in self.accounts:
            label = acc.get("label", "未命名")
            issuer = acc.get("issuer", "")
            self.list.insert(tk.END, f"{label}" + (f" ({issuer})" if issuer else ""))

    def tick(self):
        lines = []
        for acc in self.accounts:
            try:
                secret = decode_secret(acc.get("secret", ""))
                digits = int(acc.get("digits", 6))
                period = int(acc.get("period", 30))
                code, rem = totp(secret, period=period, digits=digits)
                lines.append(f"{acc.get('label','未命名')}: {code}  剩余 {rem}s")
            except Exception:
                lines.append(f"{acc.get('label','未命名')}: 密钥无效")
        self.status.config(text="  |  ".join(lines))
        self.root.after(1000, self.tick)

    def add_account(self):
        label = simpledialog.askstring("添加账号", "账号名称：")
        if label is None:
            return
        issuer = simpledialog.askstring("添加账号", "发行者/平台（可选）：") or ""
        secret = simpledialog.askstring("添加账号", "密钥（Base32 或 Hex/MD5）：")
        if not secret:
            messagebox.showerror("错误", "必须填写密钥")
            return
        digits = simpledialog.askinteger("添加账号", "位数（6-8）：", initialvalue=6, minvalue=6, maxvalue=8) or 6
        period = simpledialog.askinteger("添加账号", "周期秒（15-90）：", initialvalue=30, minvalue=15, maxvalue=90) or 30
        # 校验密钥
        try:
            decode_secret(secret)
        except Exception as e:
            messagebox.showerror("错误", f"密钥格式不正确：{e}")
            return
        self.accounts.append({
            "label": label.strip(),
            "issuer": issuer.strip(),
            "secret": secret.strip(),
            "digits": int(digits),
            "period": int(period),
        })
        save_accounts(self.accounts)
        self.render()

    def delete_selected(self):
        sel = self.list.curselection()
        if not sel:
            return
        idx = sel[0]
        if messagebox.askyesno("确认", "确定删除该账号吗？"):
            self.accounts.pop(idx)
            save_accounts(self.accounts)
            self.render()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()