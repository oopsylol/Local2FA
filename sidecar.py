#!/usr/bin/env python3
import sys
import json
import base64
from pathlib import Path

APP_NAME = 'Local2FA'
APP_DIR = Path.home() / 'Library' / 'Application Support' / APP_NAME
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / 'data.json'

try:
    import qrcode
except Exception:
    qrcode = None


def read_accounts():
    if not DB_PATH.exists():
        DB_PATH.write_text('[]', 'utf-8')
        return []
    try:
        return json.loads(DB_PATH.read_text('utf-8'))
    except Exception:
        return []


def write_accounts(accounts):
    DB_PATH.write_text(json.dumps(accounts, ensure_ascii=False, indent=2), 'utf-8')


def generate_qr_b64(text: str):
    if qrcode is None:
        return None
    import io
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('ascii')


def main():
    # 使用简单子命令：read | write | qr
    if len(sys.argv) < 2:
        print('usage: sidecar [read|write|qr]')
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'read':
        data = read_accounts()
        print(json.dumps(data, ensure_ascii=False))
        sys.exit(0)
    elif cmd == 'write':
        payload = sys.stdin.read()
        try:
            data = json.loads(payload or '[]')
        except Exception:
            data = []
        write_accounts(data)
        print('ok')
        sys.exit(0)
    elif cmd == 'qr':
        if len(sys.argv) < 3:
            print('')
            sys.exit(0)
        b64 = generate_qr_b64(sys.argv[2])
        print(b64 or '')
        sys.exit(0)
    else:
        print('unknown command')
        sys.exit(1)


if __name__ == '__main__':
    main()