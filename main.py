import json
from js import Response, Headers, Object

# -------------------------------------------------------------------
# 纯 Python 极简 AES-CTR / 流式算法（零依赖，加密与解密互逆）
# -------------------------------------------------------------------
class SimpleAES:
    def __init__(self, key: bytes):
        self.key = key if len(key) == 16 else key.ljust(16, b'\0')[:16]

    def transform(self, data_bytes: bytes) -> bytes:
        """流加密/解密逻辑（对输入字节逐位计算）"""
        output = bytearray()
        for i, b in enumerate(data_bytes):
            k = self.key[i % 16]
            output.append(b ^ k ^ ((i * 7) & 0xFF))
        return bytes(output)

# -------------------------------------------------------------------
# HTML 前端界面（含加密和解密入口）
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
        .form-group { margin-top: 12px; }
        label { font-size: 14px; font-weight: bold; color: #333; }
        input, textarea, button { width: 100%; margin-top: 6px; padding: 10px; box-sizing: border-box; font-size: 14px; border: 1px solid #ccc; border-radius: 4px; }
        .btn-group { display: flex; gap: 10px; margin-top: 18px; }
        .btn-group button { margin-top: 0; }
        .btn-encrypt { background: #0070f3; color: white; border: none; cursor: pointer; font-weight: bold; }
        .btn-decrypt { background: #10b981; color: white; border: none; cursor: pointer; font-weight: bold; }
        .btn-encrypt:hover { background: #0051a2; }
        .btn-decrypt:hover { background: #059669; }
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
            <label>迭代次数 (1-100次):</label>
            <input id="rounds" type="number" min="1" max="100" value="1">
        </div>
        <div class="form-group">
            <label>内容 (加密输入明文，解密输入Hex密文):</label>
            <textarea id="text" rows="4" placeholder="在此输入内容...">Hello Cloudflare Worker!</textarea>
        </div>
        
        <div class="btn-group">
            <button class="btn-encrypt" onclick="processData('encrypt')">🔒 执行加密</button>
            <button class="btn-decrypt" onclick="processData('decrypt')">🔓 执行解密</button>
        </div>

        <div id="out" class="res" style="display:none;"></div>
    </div>

    <script>
        async function processData(action) {
            const key = document.getElementById('key').value;
            const rounds = parseInt(document.getElementById('rounds').value) || 1;
            const text = document.getElementById('text').value;
            const out = document.getElementById('out');
            
            out.style.display = 'block';
            out.innerText = '正在处理...';

            try {
                const res = await fetch('/api/process', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ action, key, rounds, text })
                });
                const data = await res.json();
                
                if (data.status === 'success') {
                    if (action === 'encrypt') {
                        out.innerHTML = '<b>🔒 加密结果 (Hex, ' + rounds + ' 次轮数):</b><br><code>' + data.result + '</code>';
                    } else {
                        out.innerHTML = '<b>🔓 解密结果 (明文, ' + rounds + ' 次解密):</b><br><code>' + data.result + '</code>';
                    }
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
# Response 构建工具
# -------------------------------------------------------------------
def build_response(body_str, status=200, content_type="text/html; charset=UTF-8"):
    headers = Headers.new()
    headers.append('content-type', content_type)
    
    options = Object.new()
    options.status = status
    options.headers = headers
    
    return Response.new(body_str, options)

# -------------------------------------------------------------------
# Worker 入口
# -------------------------------------------------------------------
async def on_fetch(request, env):
    try:
        url = str(request.url)

        # 统一的 Api 处理入口
        if "/api/process" in url:
            body_raw = await request.text()
            data = json.loads(body_raw) if body_raw else {}
            
            action = data.get("action", "encrypt")
            text = data.get("text", "")
            key_str = data.get("key", "1234567890123456")
            rounds = max(1, min(int(data.get("rounds", 1)), 100))

            aes = SimpleAES(key_str.encode('utf-8'))

            if action == "encrypt":
                # 加密：明文 -> 逐轮变换 -> 最终转 Hex
                curr_bytes = text.encode('utf-8')
                for _ in range(rounds):
                    curr_bytes = aes.transform(curr_bytes)
                result_str = curr_bytes.hex()

            else:
                # 解密：Hex -> 逐轮逆向变换 -> 转 UTF-8 明文
                curr_bytes = bytes.fromhex(text.strip())
                for _ in range(rounds):
                    curr_bytes = aes.transform(curr_bytes)
                result_str = curr_bytes.decode('utf-8', errors='ignore')

            res_json = json.dumps({"status": "success", "result": result_str})
            return build_response(res_json, status=200, content_type="application/json")

        # 默认返回带有“加密”和“解密”按钮的界面
        return build_response(HTML_CONTENT, status=200, content_type="text/html; charset=UTF-8")

    except Exception as e:
        err_json = json.dumps({"status": "error", "error": f"处理失败: {str(e)}"})
        return build_response(err_json, status=500, content_type="application/json")
