import base64
import os
import hashlib
import pyaes
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# ---------- 请求模型 ----------
class ProcessRequest(BaseModel):
    text: str
    mode: str   # base64-encode, base64-decode, aes-encrypt, aes-decrypt
    times: int
    password: Optional[str] = None

# ---------- Base64 核心逻辑 ----------
def encode_multiple(data: str, times: int) -> str:
    current = data
    for i in range(times):
        current = base64.b64encode(current.encode('utf-8')).decode('utf-8')
    return current

def decode_multiple(data: str, times: int) -> str:
    current = data
    for i in range(times):
        current = base64.b64decode(current).decode('utf-8', errors='replace')
    return current

# ---------- AES 核心逻辑 (使用纯Python库 pyaes) ----------
def pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(data: str, password: str, times: int) -> str:
    # 生成随机盐和 IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # 迭代次数 = times * 1000 (最少1000次)
    iterations = max(1000, times * 1000)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
    
    # 填充并加密
    plaintext = data.encode('utf-8')
    padded = pkcs7_pad(plaintext)
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    ciphertext = aes.encrypt(padded)
    
    # 将 salt + iv + 密文 组合并转为 Base64 便于传输
    combined = salt + iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def aes_decrypt(encoded_data: str, password: str, times: int) -> str:
    raw = base64.b64decode(encoded_data)
    
    # 提取 salt、iv 和密文
    salt = raw[:16]
    iv = raw[16:32]
    ciphertext = raw[32:]
    
    iterations = max(1000, times * 1000)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
    
    # 解密并去填充
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    decrypted_padded = aes.decrypt(ciphertext)
    plaintext = pkcs7_unpad(decrypted_padded)
    
    return plaintext.decode('utf-8')

# ---------- API 端点 ----------
@app.post("/api/process")
async def process(req: ProcessRequest):
    try:
        if req.mode == "base64-encode":
            result = encode_multiple(req.text, req.times)
        elif req.mode == "base64-decode":
            result = decode_multiple(req.text, req.times)
        elif req.mode == "aes-encrypt":
            if not req.password:
                return {"success": False, "error": "AES 加密需要提供密码"}
            result = aes_encrypt(req.text, req.password, req.times)
        elif req.mode == "aes-decrypt":
            if not req.password:
                return {"success": False, "error": "AES 解密需要提供密码"}
            result = aes_decrypt(req.text, req.password, req.times)
        else:
            return {"success": False, "error": "未知模式"}
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ---------- 前端页面 ----------
@app.get("/", response_class=HTMLResponse)
async def index():
    html = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Base64 + AES 加密工具箱</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #f1f5f9;
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 860px;
            width: 100%;
            background: white;
            border-radius: 24px;
            padding: 32px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.06);
        }
        h1 {
            font-size: 26px;
            font-weight: 600;
            margin: 0 0 4px 0;
            color: #0f172a;
        }
        .badge {
            display: inline-block;
            background: #e2e8f0;
            padding: 2px 12px;
            border-radius: 20px;
            font-size: 12px;
            color: #475569;
            margin-left: 8px;
        }
        .subtitle {
            color: #64748b;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .control-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 16px 20px;
            background: #f8fafc;
            padding: 16px 20px;
            border-radius: 16px;
            margin-bottom: 20px;
            align-items: center;
            border: 1px solid #e2e8f0;
        }
        .control-group {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .control-group label {
            font-weight: 500;
            color: #334155;
            font-size: 14px;
        }
        select, input[type="number"], input[type="password"] {
            padding: 6px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 14px;
            background: white;
        }
        select:focus, input:focus {
            outline: 2px solid #3b82f6;
            border-color: transparent;
        }
        .mode-select { min-width: 140px; }
        .times-input { width: 70px; text-align: center; }
        .pwd-input { width: 160px; }
        .textarea-group {
            margin-bottom: 16px;
        }
        .textarea-group label {
            display: block;
            font-weight: 500;
            margin-bottom: 6px;
            color: #0f172a;
            font-size: 14px;
        }
        textarea {
            width: 100%;
            height: 140px;
            padding: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            resize: vertical;
            background: #fafbfc;
        }
        textarea:focus {
            outline: 2px solid #3b82f6;
            border-color: transparent;
        }
        .output-area textarea {
            background: #f8fafc;
        }
        .action-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 6px 0 18px 0;
            align-items: center;
        }
        .btn {
            padding: 8px 22px;
            border: none;
            border-radius: 10px;
            font-weight: 500;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-primary {
            background: #2563eb;
            color: white;
        }
        .btn-primary:hover { background: #1d4ed8; transform: scale(0.98); }
        .btn-secondary {
            background: #e2e8f0;
            color: #1e293b;
        }
        .btn-secondary:hover { background: #cbd5e1; }
        .btn-success {
            background: #10b981;
            color: white;
        }
        .btn-success:hover { background: #059669; }
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        .btn-danger:hover { background: #dc2626; }
        .status {
            margin-left: auto;
            font-size: 14px;
            color: #94a3b8;
        }
        .status.success { color: #059669; }
        .status.error { color: #dc2626; font-weight: 500; }
        .status.loading { color: #d97706; }
        .hint {
            font-size: 12px;
            color: #94a3b8;
            margin-top: 4px;
        }
        .footer {
            margin-top: 12px;
            font-size: 13px;
            color: #94a3b8;
            text-align: center;
            border-top: 1px solid #f1f5f9;
            padding-top: 14px;
        }
        @media (max-width: 640px) {
            .container { padding: 18px; }
            .control-bar { flex-direction: column; align-items: stretch; }
            .action-bar { flex-wrap: wrap; }
            .status { margin-left: 0; }
            .pwd-input { width: 100%; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🔐 加密工具箱 <span class="badge">Base64 + AES</span></h1>
    <div class="subtitle">Base64 编解码 · AES-256-CBC 对称加密（支持自定义迭代次数）</div>

    <!-- 控制区域 -->
    <div class="control-bar">
        <div class="control-group">
            <label for="modeSelect">模式</label>
            <select id="modeSelect" class="mode-select">
                <option value="base64-encode">Base64 编码</option>
                <option value="base64-decode">Base64 解码</option>
                <option value="aes-encrypt">AES 加密</option>
                <option value="aes-decrypt">AES 解密</option>
            </select>
        </div>
        <div class="control-group" id="pwdGroup">
            <label for="password">密码</label>
            <input type="password" id="password" class="pwd-input" placeholder="加密/解密密钥">
        </div>
        <div class="control-group">
            <label for="times">轮次 (x1000)</label>
            <input type="number" id="times" class="times-input" value="10" min="1" max="999">
        </div>
    </div>

    <!-- 输入 -->
    <div class="textarea-group">
        <label for="input-text">输入</label>
        <textarea id="input-text" placeholder="请输入要处理的内容…"></textarea>
    </div>

    <!-- 操作按钮 -->
    <div class="action-bar">
        <button class="btn btn-primary" id="actionBtn">▶ 执行</button>
        <button class="btn btn-secondary" id="clearBtn">清空全部</button>
        <button class="btn btn-secondary" id="swapBtn">⇄ 交换</button>
        <button class="btn btn-success" id="copyBtn">📋 复制结果</button>
        <span class="status" id="status">就绪</span>
    </div>

    <!-- 输出 -->
    <div class="textarea-group output-area">
        <label for="output-text">输出</label>
        <textarea id="output-text" readonly></textarea>
    </div>
    <div class="hint">💡 AES 模式下，「轮次」为 PBKDF2 密钥派生迭代次数（×1000），数值越大越安全，但速度会稍慢。</div>
    <div class="footer">按 Enter 或 Ctrl+Enter 执行 · 密码和轮次需与加密时完全一致才能解密</div>
</div>

<script>
    const inputEl = document.getElementById('input-text');
    const outputEl = document.getElementById('output-text');
    const modeSelect = document.getElementById('modeSelect');
    const passwordEl = document.getElementById('password');
    const timesInput = document.getElementById('times');
    const actionBtn = document.getElementById('actionBtn');
    const clearBtn = document.getElementById('clearBtn');
    const swapBtn = document.getElementById('swapBtn');
    const copyBtn = document.getElementById('copyBtn');
    const statusEl = document.getElementById('status');
    const pwdGroup = document.getElementById('pwdGroup');

    // 根据模式显示/隐藏密码框
    function togglePasswordVisibility() {
        const mode = modeSelect.value;
        if (mode.startsWith('aes-')) {
            pwdGroup.style.display = 'flex';
        } else {
            pwdGroup.style.display = 'none';
        }
    }
    modeSelect.addEventListener('change', togglePasswordVisibility);
    togglePasswordVisibility();

    // 设置状态
    function setStatus(msg, type = '') {
        statusEl.textContent = msg;
        statusEl.className = 'status' + (type ? ' ' + type : '');
    }

    // 核心处理
    async function process() {
        const text = inputEl.value;
        if (!text) {
            setStatus('⚠️ 请输入内容', 'error');
            return;
        }
        const mode = modeSelect.value;
        const times = parseInt(timesInput.value) || 10;
        const password = passwordEl.value;

        // AES 模式必须填写密码
        if (mode.startsWith('aes-') && !password) {
            setStatus('⚠️ AES 模式需要填写密码', 'error');
            passwordEl.focus();
            return;
        }

        setStatus('⏳ 处理中…', 'loading');
        actionBtn.disabled = true;

        try {
            const resp = await fetch('/api/process', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text, mode, times, password })
            });
            const data = await resp.json();
            if (data.success) {
                outputEl.value = data.result;
                const modeLabel = modeSelect.options[modeSelect.selectedIndex].text;
                setStatus(`✅ 完成 (${modeLabel}, 轮次 ×${times})`, 'success');
            } else {
                setStatus('❌ ' + data.error, 'error');
            }
        } catch (err) {
            setStatus('❌ 网络或服务器错误', 'error');
            console.error(err);
        } finally {
            actionBtn.disabled = false;
        }
    }

    // 事件绑定
    actionBtn.addEventListener('click', process);

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            process();
        }
        if (e.key === 'Enter' && e.target === inputEl && !e.shiftKey) {
            e.preventDefault();
            process();
        }
    });

    clearBtn.addEventListener('click', () => {
        inputEl.value = '';
        outputEl.value = '';
        setStatus('已清空');
        inputEl.focus();
    });

    swapBtn.addEventListener('click', () => {
        const inVal = inputEl.value;
        const outVal = outputEl.value;
        inputEl.value = outVal;
        outputEl.value = inVal;
        setStatus('已交换');
    });

    copyBtn.addEventListener('click', async () => {
        const val = outputEl.value;
        if (!val) {
            setStatus('输出为空', 'error');
            return;
        }
        try {
            await navigator.clipboard.writeText(val);
            setStatus('✅ 已复制到剪贴板', 'success');
        } catch {
            outputEl.select();
            document.execCommand('copy');
            setStatus('✅ 已复制', 'success');
        }
    });

    // 初始化状态
    setStatus('就绪');
</script>
</body>
</html>
    """
    return html
