#!/usr/bin/env python3
import json
import base64
from pathlib import Path

import webview

APP_NAME = 'Local2FA'
APP_DIR = Path.home() / 'Library' / 'Application Support' / APP_NAME
APP_DIR.mkdir(parents=True, exist_ok=True)
# 固定使用 data.json
DEFAULT_DB = APP_DIR / 'data.json'

try:
    import qrcode
except Exception:
    qrcode = None


def get_data_path():
    # 始终使用固定文件路径
    return DEFAULT_DB


class Api:
    def __init__(self):
        # 避免将 Path 对象暴露给前端导致 pywebview 反射报错
        self.data_path = str(get_data_path())
        p = Path(self.data_path)
        if not p.exists():
            # 初始化空数组文件
            p.write_text('[]', 'utf-8')

    def read_accounts(self):
        p = Path(self.data_path)
        if not p.exists():
            return []
        try:
            return json.loads(p.read_text('utf-8'))
        except Exception:
            return []

    def write_accounts(self, accounts):
        p = Path(self.data_path)
        try:
            p.write_text(json.dumps(accounts, ensure_ascii=False, indent=2), 'utf-8')
            return True
        except Exception as e:
            return False

    # 不再提供选择文件的能力，统一使用固定 data.json
    def choose_data_file(self):
        return str(self.data_path)

    def generate_qr(self, text):
        if qrcode is None:
            # 无 qrcode 依赖时返回 None，前端可使用网络备选
            return None
        img = qrcode.make(text)
        import io
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        b64 = base64.b64encode(buf.getvalue()).decode('ascii')
        return b64


def main():
    api = Api()
    # 较小的固定尺寸窗口，专注添加与显示
    webview.create_window(
        '本机 2FA 管理器',
        str((Path(__file__).parent / 'index.html').resolve()),
        js_api=api,
        width=420,
        height=560,
        resizable=False
    )
    webview.start()


if __name__ == '__main__':
    main()