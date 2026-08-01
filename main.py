import pyaes
import json
from js import Response

async def on_fetch(request, env):
    """
    Cloudflare Python Worker 的主入口函数
    :param request: 传入的 HTTP 请求对象 (JS Request)
    :param env: 环境变量绑定对象
    """
    try:
        # 1. 解析请求方法 (GET 或 POST)
        method = request.method.upper()
        
        # 2. 从请求中获取需要处理的数据与密钥
        #    默认设置一个 16 字节 (128位) 的测试 Key 和 IV
        key = b"1234567890123456"
        text_to_encrypt = "Hello, Cloudflare Workers!"
        
        # 如果是 POST 请求，尝试从 JSON 请求体读取数据
        if method == "POST":
            try:
                body_text = await request.text()
                if body_text:
                    body = json.loads(body_text)
                    text_to_encrypt = body.get("text", text_to_encrypt)
                    custom_key = body.get("key")
                    if custom_key:
                        key = custom_key.encode('utf-8')
            except Exception:
                pass  # 请求体解析失败时使用默认值

        # 3. 执行 AES-CTR 模式加密
        aes_encryptor = pyaes.AESModeOfOperationCTR(key)
        ciphertext = aes_encryptor.encrypt(text_to_encrypt)
        ciphertext_hex = ciphertext.hex() # 转为十六进制文本方便传输

        # 4. 执行 AES-CTR 模式解密 (验证加密结果)
        aes_decryptor = pyaes.AESModeOfOperationCTR(key)
        decrypted_bytes = aes_decryptor.decrypt(ciphertext)
        decrypted_text = decrypted_bytes.decode('utf-8')

        # 5. 组装响应 JSON 结构
        response_data = {
            "status": "success",
            "message": "AES 加解密处理成功",
            "data": {
                "original_text": text_to_encrypt,
                "key_used": key.decode('utf-8', errors='ignore'),
                "encrypted_hex": ciphertext_hex,
                "decrypted_text": decrypted_text
            }
        }

        # 6. 返回 HTTP Response
        return Response.new(
            json.dumps(response_data, ensure_ascii=False),
            headers={
                "content-type": "application/json; charset=UTF-8",
                "Access-Control-Allow-Origin": "*"  # 允许跨域访问
            }
        )

    except Exception as e:
        # 捕获运行期异常并返回错误提示
        error_data = {
            "status": "error",
            "message": f"处理请求时发生错误: {str(e)}"
        }
        return Response.new(
            json.dumps(error_data, ensure_ascii=False),
            headers={"content-type": "application/json; charset=UTF-8"},
            status=500
        )
