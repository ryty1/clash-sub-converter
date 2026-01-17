# Clash Subscription Converter

基于 ACL4SSR 规则的 Clash 订阅转换服务 - **Cloudflare Workers 版本**

## 🚀 一键部署到 CF Pages

### 方式一：GitHub + CF Pages (推荐)

1. **Fork 本仓库** 或创建新仓库上传代码

2. **登录 Cloudflare Dashboard** → Pages → Create Project

3. **连接 GitHub 仓库**，配置如下：
   - Build command: _(留空)_
   - Build output: _(留空)_
   - Root directory: _(留空)_

4. **选择 Functions**：Cloudflare 会自动检测 `wrangler.toml`

5. 点击 **Deploy** 即可

### 方式二：Wrangler CLI

```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

## API 使用

```
GET /sub?url=<订阅链接>
```

| 参数 | 说明 |
|------|------|
| `url` | 订阅链接 (多个用 `\|` 分隔) |
| `target` | `clash` 或 `clash.meta` |
| `emoji` | 添加国旗 (默认 true) |
| `exclude` | 排除节点的正则 |
| `include` | 保留节点的正则 |

## 功能

- ✅ VMess/VLESS/Trojan/SS/Hysteria2/TUIC
- ✅ 50+ 地区节点分组
- ✅ ACL4SSR 广告拦截、AI 分流
- ✅ Web 可视化界面

## 文件结构

```
├── wrangler.toml      # CF Workers 配置
└── src/
    ├── worker.js      # 主入口
    ├── config.js      # 规则配置
    ├── subParser.js   # 订阅解析
    ├── clashGenerator.js
    └── frontend.js    # Web 界面
```

## License

MIT
