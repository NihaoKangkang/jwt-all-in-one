# JWT All in One

[English README](./README.md) · [中文界面](https://www.kyiwong.com/jwt-all-in-one/) · [纯英文界面](https://www.kyiwong.com/jwt-all-in-one/?lang=en)

纯前端 JWT 安全测试工作台。输入三段式 JWS 和完整 curl，选择测试类别，**一键复制完整执行命令**，粘贴到终端就能遍历所有载荷，不需要下载脚本或 payload 文件。TXT / TSV 导出保留为可选功能。

本项目继承账号的 `www.kyiwong.com` Pages 自定义域名。HTTP 访问自动升级 HTTPS。部署排队不代表已经上线，状态见 [Actions](https://github.com/NihaoKangkang/jwt-all-in-one/actions)。

## 使用

1. 输入原始 JWT。Header / Payload 可解码不代表签名有效；当前支持三段式 JWS，不支持五段式 JWE。
2. 从浏览器复制 Bash 风格完整 curl，用字面量 `$JWT_HERE` 替换 JWT：

   ```bash
   curl 'https://your-authorized-host.example/api/me' \
     -H 'Authorization: Bearer $JWT_HERE' \
     -H 'Accept: application/json'
   ```

   支持 Header、Cookie、URL、请求体及重复占位符，单引号中的占位符也会替换。仅支持一条 curl；不执行输入的 shell 源码，不接受管道、重定向、命令替换、额外变量、多条命令或 curl 输出/配置/并发选项。Windows CMD / PowerShell 格式需转换为 Bash。
3. 所有类别默认勾选，按需取消。高级配置可填写目标 RSA 公钥、自定义 Header/Payload、自有签名密钥、Fuzz 字段和值、请求间隔/超时/响应关键字。
4. 点击「生成测试载荷」，再点击「复制完整执行命令」，将**整个代码块**粘贴到有 Bash 和 curl 的终端。命令自带全部 JWT 和标签，使用 for 循环逐条执行，不依赖外部 payload 文件，也不远程下载可执行代码。
5. 逐条查看 JWT、HTTP 状态、curl 退出码、响应头、正文。结果写入 `jwt-results.XXXXXX/`：

   ```text
   summary.tsv       # 序号、标签、状态、退出码、字节数、耗时、关键字命中、基线正文比较
   0001.jwt.txt      # 本次载荷
   0001.headers      # 响应头
   0001.body         # 响应正文
   0001.stderr       # curl 错误
   ```

   某次失败后继续。默认间隔 0.2 秒、超时 30 秒；可设置 0–60 秒间隔与 1–300 秒超时，连接超时 10 秒。兼容 macOS Bash 3 与 Linux Bash。没有启用原始基线时，正文比较为 n/a。

## 已实现

- 13 个测试类别：基线、none、签名变形、空/弱 HMAC secret、RS/HS 混淆、内嵌 JWK、JKU/x5u、kid、Claims、Header/Parser、ECDSA 零值、自定义签名、字段 Fuzz。
- 自有密钥签名与验签：HS256/384/512、RS256/384/512、PS256/384/512、ES256/384/512、EdDSA（Ed25519）。接收 secret、PKCS#8 私钥、SPKI 公钥、JWK / JWKS；浏览器不支持的算法明确报错。
- Header/Payload JSON 编辑、自有密钥重签名。勾选签名选项后，空 HMAC 输入表示真正的空密钥。
- 任意 Header / Payload 点路径 Fuzz，每行一个 JSON 值或字符串，最多 50 个值，可组合已选签名方式。
- HMAC 离线字典实际检查原始签名，最多 10,000 个候选，额外测试空密钥，Worker 内运行，有进度、可取消。
- 浏览器生成 RSA-2048、P-256/384/521、Ed25519 密钥，导出 PKCS#8、SPKI、公有 JWKS；从 JWK/JWKS 导出公钥 PEM。
- 一键复制全部 JWT 或完整执行命令；可选 TXT / TSV；中英文切换，英文直达 `?lang=en`。

HTTP 200、关键字命中或正文相同均不自动等于漏洞。部分篡改故意保留原签名，检测目标是否忽略完整性校验。验签只检查签名及数字 exp/nbf 时间范围，不替代 issuer/audience 信任、身份、权限和业务校验。

HMAC 的自动输入格式始终把内容当作原始 secret，包括以 `{` 开头或看似 JSON 的密钥。要导入 HMAC JWK，请明确选择「JWK / JWKS JSON」。离线字典候选永远按原始字符串检查，不会当作 JWK。

## 公开密钥与隐私

`keys/` 中两对 RSA-2048、一对 P-256、JWKS 和匹配的 RSA-A 证书**刻意公开，仅供实验，不能用于真实认证**。同样的材料打包在 `src/keys.js`。RS/HS 混淆必须提供目标实际公钥，仓库公钥不能代替；自定义 JKU/x5u URL 必须托管匹配公钥/证书。本地生成的密钥不会发布。

没有后端、CDN、分析脚本、运行时第三方依赖或 Token 持久化。输入只在页面内存，CSP `connect-src 'none'` 阻止 fetch/XHR；页面、模块和 Worker 初次加载仍访问托管站点。只有手动执行终端命令后才向目标发请求。复制的命令包含请求凭证，请本地保存。

## 本地开发与部署

无需安装或构建：

```bash
python3 -m http.server 4173 --bind 127.0.0.1
# http://127.0.0.1:4173/
```

Node.js 22+、curl：

```bash
npm test
```

测试包含 13 种签名算法的独立 Node crypto 验签、密钥一致性、字典、Fuzz、类别过滤，以及对本地 HTTP 服务真实执行复制命令。

页面入口、模块间导入、Worker、CSS 和默认公开密钥 URL 使用统一发布版本参数，避免 CDN 缓存混用。修改发布版本时更新 package.json 并运行 `npm run version-assets`；`npm test` 会检查版本标记一致性。

工作流在 PR 运行测试，推送 main 后测试并部署。Pages Source 选择 GitHub Actions；发布文件仅含页面、favicon、src/ 和 keys/，相对路径支持项目子目录。

独立参考 [jwt_tool](https://github.com/ticarpi/jwt_tool) 思路实现，未复制 GPL 源码；不是完整 CLI 兼容实现。MIT License。仅用于已获授权的环境。
