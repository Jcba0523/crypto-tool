import pyaes
import json
from js import Response

# 这里放入你的前端 HTML 页面代码
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>AES 加解密工具</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
        textarea, input { width: 100%; margin-bottom: 10px; padding: 8px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background-color: #0070f3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .result { margin-top: 20px; background: #f4f4f4; padding: 15px; border-radius: 4px; word-break: break-all; }
    </style>
</head>
<body>
    <h2>AES 加解密工具</h2>
    <label>密钥 (Key - 16位):</label>
    <input type="text" id="key" value="1234567890123456">
    
    <label>明文内容:</label>
    <textarea id="text" rows="4">Hello Cloudflare!</textarea>
    
    <button onclick="doEncrypt()">提交加密</button>
    
    <div class="result" id="result" style="display:none;"></div>

    <script>
        async function doEncrypt() {
            const key = document.getElementById('key').value;
            const text = document.getElementById('text').value;
            
            const res = await fetch('/api/encrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key, text })
            });
            
            const data = await res.json();
            document.getElementById('result').style.display = 'block';
            document.getElementById('result').innerHTML = '<b>加密结果 (Hex):</b><br>' + data.data.encrypted_hex;
        }
    </script>
</body>
</html>
"""

async def on_fetch(request, env):
    # 获取请求路径
    url = request.url
    
    # 1. 如果访问的是 /api/encrypt，则走加解密逻辑 (返回 JSON)
    if "/api/encrypt" in url:
        try:
            body_text = await request.text()
            body = json.loads(body_text) if body_text else {}
            
            text_to_encrypt = body.get("text", "Hello")
            key = body.get("key", "1234567890123456").encode('utf-8')

            aes_encryptor = pyaes.AESModeOfOperationCTR(key)
            ciphertext = aes_encryptor.encrypt(text_to_encrypt)

            return Response.new(
                json.dumps({
                    "status": "success",
                    "data": {
                        "encrypted_hex": ciphertext.hex()
                    }
                }),
                headers={"content-type": "application/json; charset=UTF-8"}
            )
        except Exception as e:
            return Response.new(json.dumps({"error": str(e)}), status=500)

    # 2. 如果访问的是首页根路径，直接返回图形界面 (HTML)
    return Response.new(
        HTML_CONTENT,
        headers={"content-type": "text/html; charset=UTF-8"}
    )
