/**
 * HTML Frontend Template - CF Workers Version
 */

export const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Clash 订阅转换</title>
  <style>
    :root { --bg: #0f0f23; --card: #16213e; --accent: #6366f1; --text: #e2e8f0; --border: #334155; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%); min-height: 100vh; color: var(--text); padding: 20px; }
    .container { max-width: 800px; margin: 0 auto; }
    header { text-align: center; padding: 40px 0; }
    h1 { font-size: 2.2rem; background: linear-gradient(135deg, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
    .subtitle { color: #94a3b8; }
    .card { background: var(--card); border-radius: 16px; padding: 25px; margin-bottom: 20px; border: 1px solid var(--border); }
    label { display: block; margin-bottom: 6px; color: #94a3b8; font-size: 0.9rem; }
    input, textarea { width: 100%; padding: 12px; background: #1a1a2e; border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 1rem; margin-bottom: 15px; }
    input:focus, textarea:focus { outline: none; border-color: var(--accent); }
    textarea { min-height: 100px; resize: vertical; }
    .checkbox-group { display: flex; gap: 15px; margin-bottom: 15px; }
    .checkbox-item { display: flex; align-items: center; gap: 6px; cursor: pointer; }
    .checkbox-item input { width: 16px; height: 16px; }
    .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; border: none; border-radius: 10px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.3s; }
    .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4); }
    .result { display: none; }
    .result.show { display: block; }
    .result-url { word-break: break-all; padding: 12px; background: #1a1a2e; border-radius: 8px; margin-bottom: 12px; font-family: monospace; font-size: 0.85rem; }
    .btn-group { display: flex; gap: 10px; }
    .btn-group .btn { flex: 1; }
    .copy-btn { background: #22c55e; }
    .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 20px; }
    .feature { display: flex; align-items: center; gap: 8px; padding: 12px; background: #1a1a2e; border-radius: 8px; border: 1px solid var(--border); }
    .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #22c55e; color: white; padding: 12px 24px; border-radius: 8px; opacity: 0; transition: opacity 0.3s; }
    .toast.show { opacity: 1; }
    footer { text-align: center; padding: 30px 0; color: #94a3b8; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🚀 Clash 订阅转换</h1>
      <p class="subtitle">基于 ACL4SSR 规则 · Cloudflare Workers</p>
    </header>
    <div class="card">
      <label>订阅链接 *</label>
      <textarea id="subUrl" placeholder="请输入订阅链接，多个链接用换行分隔"></textarea>
      <label>选项</label>
      <div class="checkbox-group">
        <label class="checkbox-item"><input type="checkbox" id="emoji" checked><span>添加国旗 Emoji</span></label>
        <label class="checkbox-item"><input type="checkbox" id="useMeta"><span>Clash Meta 格式</span></label>
      </div>
      <label>排除节点 (正则)</label>
      <input type="text" id="exclude" placeholder="例如: 过期|剩余|套餐">
      <button class="btn" onclick="generateUrl()">生成订阅链接</button>
    </div>
    <div class="card result" id="resultSection">
      <h3 style="margin-bottom:12px">📋 转换结果</h3>
      <div class="result-url" id="resultUrl"></div>
      <div class="btn-group">
        <button class="btn copy-btn" onclick="copyUrl()">复制链接</button>
        <button class="btn" style="background:#334155" onclick="openUrl()">测试链接</button>
      </div>
    </div>
    <div class="card">
      <h3 style="margin-bottom:12px">✨ 功能特性</h3>
      <div class="features">
        <div class="feature">🌐 支持多种协议</div>
        <div class="feature">🗺️ 150+ 地区分组</div>
        <div class="feature">🚫 广告拦截规则</div>
        <div class="feature">🤖 AI/OpenAI 分流</div>
        <div class="feature">📺 流媒体分流</div>
        <div class="feature">⚡ 自动测速选优</div>
      </div>
    </div>
    <footer>Powered by ACL4SSR Rules · Cloudflare Workers</footer>
  </div>
  <div class="toast" id="toast">已复制到剪贴板</div>
  <script>
    function generateUrl() {
      const subUrl = document.getElementById('subUrl').value.trim();
      if (!subUrl) return alert('请输入订阅链接');
      const urls = subUrl.split('\\n').filter(u => u.trim()).join('|');
      const params = new URLSearchParams();
      params.set('url', urls);
      params.set('target', document.getElementById('useMeta').checked ? 'clash.meta' : 'clash');
      params.set('emoji', document.getElementById('emoji').checked ? 'true' : 'false');
      const exclude = document.getElementById('exclude').value.trim();
      if (exclude) params.set('exclude', exclude);
      const queryString = params.toString()
        .replace(/%3A/gi, ':')
        .replace(/%2F/gi, '/')
        .replace(/%3F/gi, '?')
        .replace(/%3D/gi, '=');
      const resultUrl = location.origin + '/sub?' + queryString;
      document.getElementById('resultUrl').textContent = resultUrl;
      document.getElementById('resultSection').classList.add('show');
    }
    function copyUrl() {
      navigator.clipboard.writeText(document.getElementById('resultUrl').textContent);
      const t = document.getElementById('toast'); t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2000);
    }
    function openUrl() { window.open(document.getElementById('resultUrl').textContent, '_blank'); }
  </script>
</body>
</html>`;
