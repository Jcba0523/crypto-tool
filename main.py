import pyaes
import json
from js import Response

# 这里是你的前端图形界面 HTML 代码
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES 加解密工具</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background-color: #f9f9f9; }
        .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        label { display: block; margin-top: 12px; font-weight: bold; color: #555; }
        textarea, input { width: 100%; margin-top: 6px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
        button { width: 100%; margin-top: 18px; padding: 12px; background-color: #0070f3; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background-color: #0051a2; }
        .result { margin-top: 20px; background: #eef2ff; padding: 15px; border-radius: 4px; border: 1px solid #c7d2fe; word-break: break-all; }
    </style>
</head>
<body>
    <div class="card">
        <h2>AES 加解密工具</h2>
        <label>密钥 (Key - 16位字符):</label>
        <input type="text" id="key" value="1234567890123456">
        
        <label>待加密明文:</label>
        <textarea id="text" rows="4">Hello, Cloudflare Workers!</textarea>
        
        <button onclick="doEncrypt()">执行 AES 加密</button>
        
        <div class="result" id="result" style="display:none;"></div>
    </div>

    <script>
        async function doEncrypt() {
            const key = document.getElementById('key').value;
            const text = document.getElementById('text').value;
            const resDiv = document.getElementById('result');
            
            resDiv.style.display = 'block';
            resDiv.innerHTML = '正在加密...';

            try {
                const res = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key, text })
                });
                
                const data = await res.json();
                if (data.status === 'success') {
                    resDiv.innerHTML = '<b>加密成功 (Hex):</b><br><code>' + data.data.encrypted_hex + '</code>';
                } else {
                    resDiv.innerHTML = '<span style="color:red;">错误: ' + data.message + '</span>';
                }
            } catch (err) {
                resDiv.innerHTML = '<span style="color:red;">请求失败，请检查网络</span>';
            }
        }
    </script>
</body>
</html>
"""

async def on_fetch(request, env):
    try:
        # 获取 JS Request 对象的 url 字符串
        url_str = str(request.url)
        
        # 1. 如果请求路径包含 /api/encrypt，走后端加解密接口
        if "/api/encrypt" in url_str:
            body_text = await request.text()
            body = json.loads(body_text) if body_text else {}
            
            text_to_encrypt = body.get("text", "Hello")
            custom_key = body.get("key", "1234567890123456")
            
            # 确保 Key 为 16 字节
            key_bytes = custom_key.encode('utf-8')
            if len(key_bytes) != 16:
                key_bytes = key_bytes.ljust(16, b'\0')[:16]

            # 执行 AES-CTR 加密
            aes_encryptor = pyaes.AESModeOfOperationCTR(key_bytes)
            ciphertext = aes_encryptor.encrypt(text_to_encrypt)

            res_payload = {
                "status": "success",
                "data": {
                    "original": text_to_encrypt,
                    "encrypted_hex": ciphertext.hex()
                }
            }
            return Response.new(
                json.dumps(res_payload, ensure_ascii=False),
                headers={"content-type": "application/json; charset=UTF-8"}
            )

        # 2. 访问根目录或其他路径时，直接返回前端网页 (HTML)
        return Response.new(
            HTML_CONTENT,
            headers={"content-type": "text/html; charset=UTF-8"}
        )

    except Exception as e:
        # 捕获全局异常，避免抛出 Error 1101
        error_res = {
            "status": "error",
            "message": str(e)
        }
        return Response.new(
            json.dumps(error_res, ensure_ascii=False),
            headers={"content-type": "application/json; charset=UTF-8"},
            status=500
        )
