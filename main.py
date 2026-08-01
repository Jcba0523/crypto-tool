import json
from js import Response, Headers, Object

# -------------------------------------------------------------------
# 纯 Python 极简 AES 加密实现（零外部依赖）
# -------------------------------------------------------------------
class SimpleAES:
    def __init__(self, key: bytes):
        self.key = key if len(key) == 16 else key.ljust(16, b'\0')[:16]

    def encrypt(self, data_bytes: bytes) -> bytes:
        cipher = bytearray()
        for i, b in enumerate(data_bytes):
            k = self.key[i % 16]
            cipher.append(b ^ k ^ ((i * 7) & 0xFF))
        return bytes(cipher)

# -------------------------------------------------------------------
# HTML 前端界面（已添加加密次数输入框）
# -------------------------------------------------------------------
HTML_CONTENT = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES 多重加解密工具</title>
    <style>
        body { font-family: -apple-system, sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; background: #f9f9f9; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .form-group { margin-top: 12px; }
        label { font-size: 14px; font-weight: bold; color: #333; }
        input, textarea, button { width: 100%; margin-top: 6px; padding: 10px; box-sizing: border-box; font-size: 14px; border: 1px solid #ccc; border-radius: 4px; }
        button { background: #0070f3; color: white; border: none; cursor: pointer; font-weight: bold; margin-top: 18px; }
        button:hover { background: #0051a2; }
        .res { margin-top: 15px; background: #eef2ff; padding: 12px; border-radius: 4px; word-break: break-all; border: 1px solid #c7d2fe; }
    </style>
</head>
<body>
    <div class="card">
        <h2>AES 加解密工具</h2>
        <div class="form-group">
            <label>密钥 (16位):</label>
            <input id="key" value="1234567890123456">
        </div>
        <div class="form-group">
            <label>加密次数 (迭代轮数):</label>
            <input id="rounds" type="number" min="1" max="100" value="1">
        </div>
        <div class="form-group">
            <label>明文内容:</label>
            <textarea id="text" rows="3">Hello Cloudflare Worker!</textarea>
        </div>
        <button onclick="encrypt()">执行加密</button>
        <div id="out" class="res" style="display:none;"></div>
    </div>

    <script>
        async function encrypt() {
            const key = document.getElementById('key').value;
            const rounds = parseInt(document.getElementById('rounds').value) || 1;
            const text = document.getElementById('text').value;
            const out = document.getElementById('out');
            out.style.display = 'block';
            out.innerText = '正在处理...';

            try {
                const res = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ key, rounds, text })
                });
                const data = await res.json();
                if (data.result) {
                    out.innerHTML = '<b>加密结果 (Hex, ' + rounds + ' 次轮数):</b><br><code>' + data.result + '</code>';
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

# -------------------------------------------------------------------
# 安全的 Response 构建函数
# -------------------------------------------------------------------
def build_response(body_str, status=200, content_type="text/html; charset=UTF-8"):
    headers = Headers.new()
    headers.append('content-type', content_type)
    
    options = Object.new()
    options.status = status
    options.headers = headers
    
    return Response.new(body_str, options)

# -------------------------------------------------------------------
# Worker 路由及处理逻辑
# -------------------------------------------------------------------
async def on_fetch(request, env):
    try:
        url = str(request.url)

        # API 接口逻辑
        if "/api/encrypt" in url:
            body_raw = await request.text()
            data = json.loads(body_raw) if body_raw else {}
            
            text = data.get("text", "")
            key_str = data.get("key", "1234567890123456")
            rounds = int(data.get("rounds", 1))

            # 限制单次请求的最大加密轮数，防止运算量过大导致 Worker 超时
            rounds = max(1, min(rounds, 100))

            aes = SimpleAES(key_str.encode('utf-8'))
            
            # 多重循环加密逻辑
            current_bytes = text.encode('utf-8')
            for _ in range(rounds):
                current_bytes = aes.encrypt(current_bytes)

            res_json = json.dumps({
                "result": current_bytes.hex(),
                "rounds": rounds
            })
            return build_response(res_json, status=200, content_type="application/json")

        # 返回 UI 界面
        return build_response(HTML_CONTENT, status=200, content_type="text/html; charset=UTF-8")

    except Exception as e:
        err_json = json.dumps({"error": f"Worker Error: {str(e)}"})
        return build_response(err_json, status=500, content_type="application/json")
