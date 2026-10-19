# JWT All in One

纯前端 JWT 安全测试工作台。输入三段式 JWT 和带 `$JWT_HERE` 占位符的 curl 请求，在浏览器本地生成测试载荷，导出 TXT、说明表和 Bash 脚本。

**在线地址：<https://www.kyiwong.com/jwt-all-in-one/>**。本项目继承账号已有 Pages 自定义域名；GitHub 默认地址会重定向到该域名。应用自动升级非本机的 HTTP 访问为 HTTPS，以满足 Web Crypto 要求。

## 使用

1. 输入三段式 JWS。页面展示 Header / Payload，**可解码不代表签名已验证**；暂不支持五段式 JWE。
2. 粘贴浏览器「Copy as cURL (bash)」得到的完整请求，用字面量 `$JWT_HERE` 替换 JWT：

   ```bash
   curl 'https://your-authorized-host.example/api/me' \
     -H 'Authorization: Bearer $JWT_HERE' \
     -H 'Accept: application/json'
   ```

   占位符可位于 Header、Cookie、URL、请求体，也可重复出现；单引号中的占位符会正确替换。仅解析单条 curl，保留实际参数，不执行输入的 shell 代码。命令替换、管道、其他 shell 变量、输出覆盖、配置文件与并发选项会被拒绝。Windows CMD / PowerShell 格式请转换为 Bash 格式。
3. 所有类别默认勾选。按需取消、配置目标公钥或编辑自定义 Payload，点击「生成测试载荷」。修改输入会清除旧结果。
4. 下载 `payloads.txt`、`payload-manifest.tsv`、`jwt-runner.sh`，放到同一目录，在终端执行：

   ```bash
   bash jwt-runner.sh payloads.txt
   ```

   脚本通过 `for` 循环串行执行，每次间隔 0.2 秒，连接超时 10 秒，单次总超时 30 秒；支持 macOS 内置 Bash 3 和 Linux Bash。逐条显示 JWT、HTTP 状态、curl 退出码、响应头和正文；失败后继续执行。结果保存到新建目录：

   ```text
   jwt-results.XXXXXX/
     summary.tsv       # 序号、说明、HTTP 状态、退出码、字节数、耗时
     0001.jwt.txt      # 本次载荷
     0001.headers      # 响应头
     0001.body         # 响应正文
     0001.stderr       # curl 错误
     ...
   ```

   保持同一批次文件配套：更改 TXT 顺序后，脚本内嵌说明会错位。脚本、载荷和结果可能包含凭证，请保存在本地。

## 测试范围

| 类别 | 内容 / 条件 |
| --- | --- |
| 原始基线 | 原 JWT 逐字节保留 |
| alg=none | 四种大小写，空签名 / 无尾点；关闭后也停止生成自定义和重复 alg 中的 none 组合 |
| 签名变形 | 空签名、缺段、截断、首字符变更、随机签名、多余分段 |
| HMAC | HS256 / 384 / 512 空密钥、少量常见弱密钥和附加字典 |
| RS/HS 混淆 | 目标 RSA 公钥 PEM（LF / CRLF / 无尾换行）和 DER 作为 HMAC 密钥；未填目标公钥则跳过 |
| JWK 注入 | 两对 RSA 与一对 P-256 公钥内嵌，使用对应私钥正确签名 |
| JKU / x5u | 公开 JWKS / X.509 证书 URL，使用对应测试私钥签名 |
| kid | 空值、不存在值、路径遍历、空文件、SQL 字符串；原签名 / 空 HMAC 密钥组合 |
| Claims | sub、role、admin、isAdmin、exp、nbf、iat、iss、aud 单项变更及删除 |
| Header / Parser | typ、未知 alg、crit、b64、重复 alg、Base64URL 填充与 Base64 字符变形 |
| ECDSA | ES256 / 384 / 512 全零 JOSE 签名及故意非 JOSE 的 DER 变形 |
| 自定义 | JSON 对象，原签名及已勾选的 none / 空 HMAC / JWK 签名组合 |

参考 [jwt_tool](https://github.com/ticarpi/jwt_tool) 测试思路独立实现，没有复制其 GPL 源码。此应用不完全替代 jwt_tool：没有在线探测、自动漏洞判定、高速破解或 JWE 支持。已实现的是有限测试集合，并非穷举所有漏洞。

Claims 和部分 Header 变形保留旧签名，用于检查目标是否忽略签名验证；正常实现应拒绝。HTTP 200 不代表绕过，应与原基线比较实际身份、权限和业务内容。弱密钥载荷是使用候选 secret 签名，不是在页面确认或破解原 JWT。浏览器不向目标发请求，请求仅在你手动执行脚本后发生。

## 公开测试密钥

[`keys/`](./keys/) 保存两对 RSA-2048、一对 P-256、公开 JWKS 和与 RSA-A 匹配的自签名证书。**私钥刻意公开，仅供实验，禁止用于真实认证。** 默认 JKU / x5u URL 根据部署路径生成；自定义 URL 需要托管相同公钥 / 证书。RS/HS 混淆必须输入目标自身公钥，不能用仓库公钥代替。

同样的材料打包在 [`src/keys.js`](./src/keys.js)，生成期间不 fetch。更新密钥时需同步模块、PEM、JWKS 和证书；测试会校验一致性。

## 本地开发

无需安装依赖或构建，使用静态 HTTP 服务（不能直接双击 HTML）：

```bash
git clone https://github.com/NihaoKangkang/jwt-all-in-one.git
cd jwt-all-in-one
python3 -m http.server 4173 --bind 127.0.0.1
# 访问 http://127.0.0.1:4173
```

需要现代浏览器与 Web Crypto（HTTPS 或 localhost）。Token 和请求仅在页面内存，没有 localStorage、分析脚本、CDN 或运行时第三方依赖。CSP `connect-src 'none'` 禁止 fetch / XHR 等应用连接；首次加载页面和静态模块仍需访问静态站点。

## 测试与部署

Node.js 22+，无 npm 依赖：

```bash
npm test
# 或 node --test
```

测试覆盖 UTF-8 解析、HMAC 与 Node crypto 一致性、RSA / EC 独立验签、密钥一致性、类别过滤，以及脚本对本地 HTTP 服务的实际请求与响应保存、失败继续执行。

[GitHub Actions 工作流](./.github/workflows/pages.yml) 在 PR 运行测试，推送 `main` 后测试并部署静态文件。首次在仓库 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**，再从 Actions 运行工作流或推送 `main`。发布目录仅含页面、favicon、`src/` 和 `keys/`，无后端。所有资源使用相对路径，支持 `/jwt-all-in-one/` 项目路径。

MIT License。仅在你拥有权限的环境使用。
