import json
import pyaes
from js import Response

# 纯静态 HTML 界面
HTML_CONTENT = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES 加解密工具</title>
    <style>
        body { font-family: sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; }
        input, textarea, button { width: 100%; margin-top: 10px; padding: 10px; box-sizing: border-box; }
        button { background: #0070f3; color: white; border: none; cursor: pointer; }
        .res { margin-top: 15px; background: #f0f0f0; padding: 10px; word-break: break-all; }
    </style>
</head>
<body>
    <h3>AES 加密工具 (Worker)</h3>
    <input id="key" value="1234567890123456" placeholder="密钥(16位)">
    <textarea id="text" placeholder="输入要加密的内容">Hello World</textarea>
    <button onclick="encrypt()">点击加密</button>
    <div id="out" class="res"></div>

    <script>
        async function encrypt() {
            const key = document.getElementById('key').value;
            const text = document.getElementById('text').value;
            const res = await fetch('/api/encrypt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ key, text })
            });
            const data = await res.json();
            document.getElementById('out').innerText = data.result || data.error;
        }
    </script>
</body>
</html>"""

async def on_fetch(request, env):
    # 安全获取 URL
    try:
        url = str(request.url)
    except Exception as e:
        url = ""

    # API 路径处理
    if "/api/encrypt" in url:
        try:
            body_raw = await request.text()
            data = json.loads(body_raw) if body_raw else {}
            
            text = data.get("text", "")
            key_str = data.get("key", "1234567890123456")
            
            # 处理 16 字节 Key
            key_bytes = key_str.encode('utf-8')
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\0')
            else:
                key_bytes = key_bytes[:16]

            # 执行加密
            aes = pyaes.AESModeOfOperationCTR(key_bytes)
            cipher = aes.encrypt(text)

            return Response.new(
                json.dumps({"result": cipher.hex()}),
                headers={"content-type": "application/json"}
            )
        except Exception as err:
            return Response.new(
                json.dumps({"error": str(err)}),
                headers={"content-type": "application/json"},
                status=500
            )

    # 默认返回 HTML
    return Response.new(
        HTML_CONTENT,
        headers={"content-type": "text/html; charset=UTF-8"}
    )
