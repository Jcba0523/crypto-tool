import json
import pyaes
from js import Response, Object

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
        .res { margin-top: 15px; background: #f0f0f0; padding: 12px; border-radius: 4px; word-break: break-all; }
    </style>
</head>
<body>
    <div class="card">
        <h2>AES 加解密工具</h2>
        <label>密钥 (16位):</label>
        <input id="key" value="1234567890123456">
        <label>明文内容:</label>
        <textarea id="text" rows="3">Hello Cloudflare Worker!</textarea>
        <button onclick="encrypt()">执行 AES 加密</button>
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
                    out.innerHTML = '<b>加密结果 (Hex):</b><br>' + data.result;
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

def make_response(body_content, status=200, content_type="text/html; charset=UTF-8"):
    headers = Object.new()
    headers['content-type'] = content_type
    
    options = Object.new()
    options['status'] = status
    options['headers'] = headers
    
    return Response.new(body_content, options)

# 确保暴露 on_fetch 函数
async def on_fetch(request, env):
    try:
        url = str(request.url)

        if "/api/encrypt" in url:
            body_raw = await request.text()
            data = json.loads(body_raw) if body_raw else {}
            
            text = data.get("text", "")
            key_str = data.get("key", "1234567890123456")
            
            key_bytes = key_str.encode('utf-8')
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\0')
            else:
                key_bytes = key_bytes[:16]

            aes = pyaes.AESModeOfOperationCTR(key_bytes)
            cipher = aes.encrypt(text)

            res_json = json.dumps({"result": cipher.hex()})
            return make_response(res_json, status=200, content_type="application/json")

        return make_response(HTML_CONTENT, status=200, content_type="text/html; charset=UTF-8")

    except Exception as e:
        err_json = json.dumps({"error": str(e)})
        return make_response(err_json, status=500, content_type="application/json")

# 必须加上这条导出，告诉 Cloudflare 这是默认入口
class DefaultHandler:
    async def fetch(self, request, env, ctx):
        return await on_fetch(request, env)

# 兼容两种 Cloudflare 导出语法
__all__ = ["on_fetch"]
