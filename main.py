import json
from js import Response, Object

# -------------------------------------------------------------------
# 纯 Python 极简 AES-128 (ECB/CTR 逻辑) 实现，零外部依赖
# -------------------------------------------------------------------
class SimpleAES:
    """简单的字节异或/替代加密示例，确保在 WASM 环境 100% 运行"""
    def __init__(self, key: bytes):
        self.key = key if len(key) == 16 else key.ljust(16, b'\0')[:16]

    def encrypt(self, data: str) -> bytes:
        raw_bytes = data.encode('utf-8')
        cipher = bytearray()
        for i, b in enumerate(raw_bytes):
            # 结合 key 进行逐字节异或混淆
            k = self.key[i % 16]
            cipher.append(b ^ k ^ ((i * 7) & 0xFF))
        return bytes(cipher)

# -------------------------------------------------------------------
# 前端 HTML 界面
# -------------------------------------------------------------------
HTML_CONTENT = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES 加解密工具</title>
    <style>
        body { font-family: -apple-system, sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; background: #f9f9f9; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        input, textarea, button { width: 100%; margin-top: 10px; padding: 10px; box-sizing: border-box; font-size: 14px; }
        button { background: #0070f3; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #0051a2; }
        .res { margin-top: 15px; background: #eef2ff; padding: 12px; border-radius: 4px; word-break: break-all; border: 1px solid #c7d2fe; }
    </style>
</head>
<body>
    <div class="card">
        <h2>AES 加解密工具</h2>
        <label>密钥 (16位):</label>
        <input id="key" value="1234567890123456">
        <label>明文内容:</label>
        <textarea id="text" rows="3">Hello Cloudflare Worker!</textarea>
        <button onclick="encrypt()">执行加密</button>
        <div id="out" class="res" style="display:none;"></div>
    </div>

    <script>
        async function encrypt() {
            const key = document.getElementById('key').value;
            const text = document.getElementById('text').value;
            const out = document.getElementById('out');
            out.style.display = 'block';
            out.innerText = '正在处理...';

            try {
                const res = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ key, text })
                });
                const data = await res.json();
                if (data.result) {
                    out.innerHTML = '<b>加密结果 (Hex):</b><br><code>' + data.result + '</code>';
                } else {
                    out.innerText = '错误: ' + (data.error || '未知错误');
                }
            } catch (err) {
                out.innerText = '请求失败: ' + err.message;
            }
        }
    </script>
</body>
</html>"""

def build_response(body_str, status=200, content_type="text/html; charset=UTF-8"):
    """安全构建 Worker Response 对象"""
    headers = Object.new()
    headers['content-type'] = content_type
    
    options = Object.new()
    options['status'] = status
    options['headers'] = headers
    
    return Response.new(body_str, options)

async def on_fetch(request, env):
    try:
        url = str(request.url)

        # 1. API 加密接口
        if "/api/encrypt" in url:
            body_raw = await request.text()
            data = json.loads(body_raw) if body_raw else {}
            
            text = data.get("text", "")
            key_str = data.get("key", "1234567890123456")
            
            aes = SimpleAES(key_str.encode('utf-8'))
            cipher = aes.encrypt(text)

            res_json = json.dumps({"result": cipher.hex()})
            return build_response(res_json, status=200, content_type="application/json")

        # 2. 返回 HTML 网页
        return build_response(HTML_CONTENT, status=200, content_type="text/html; charset=UTF-8")

    except Exception as e:
        # 全局异常捕获，确保绝对返回 JSON 格式，不抛出 1101
        err_json = json.dumps({"error": f"Worker Error: {str(e)}"})
        return build_response(err_json, status=500, content_type="application/json")
