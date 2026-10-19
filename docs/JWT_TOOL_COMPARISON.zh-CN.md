# 与 jwt_tool 的功能对照及边界

这份说明用于项目验收，不输出在应用页面。对照 jwt_tool 官方 README 和使用文档，按“已经补齐”“可继续扩展”“浏览器无法独立完成”分类。所有实现都是独立编写，没有复制 jwt_tool 的 GPL 源码。

## 已经在本项目实现

1. **解码与结构检查**：UTF-8 Header / Payload，三段式 JWS。明确区分“可解码”和“签名有效”。
2. **已知测试载荷**：none、空签名、签名变形、空 HMAC secret、RS/HS 混淆、内嵌 JWK、JKU、x5u、kid、重复 alg、crit、编码变形、ECDSA r=s=0 等。
3. **已知密钥验签与重签名**：HS256/384/512、RS256/384/512、PS256/384/512、ES256/384/512、EdDSA（Ed25519）；接收 secret、PKCS#8 / SPKI PEM、JWK 和 JWKS。浏览器必须支持对应 Web Crypto 算法，异常会明确返回。
4. **自定义 Header / Payload 与时间篡改**：JSON 编辑，原签名、none、空 HMAC、注入测试公钥及自有密钥签名。
5. **自定义字段 Fuzz**：Header / Payload 点路径、每行 JSON 值或字符串，最多 50 个值；可组合已选 none / HMAC 或自有密钥重签名。阻止原型污染路径。
6. **本地 HMAC 字典检查**：Worker 中实际验证原签名；支持 10,000 个候选和空密钥，有进度、可取消。找到一个候选只说明该 secret 能验证当前 JWT，不等于任意 JWT 均可破解。
7. **RSA / EC / Ed25519 密钥生成与 JWKS 公钥重建**：本地生成可导出的 PKCS#8、SPKI 和公有 JWKS；从公有 JWK / JWKS 导出公钥 PEM。公钥不能反推出对应私钥。
8. **批量请求及结果关联**：一键复制完整 Bash 命令，内嵌所有 payload，以 for 循环调用 curl。输出每个 JWT、状态、响应头、正文、耗时、退出码与逐条文件。
9. **限速、超时和响应比较**：可设置 0–60 秒间隔、1–300 秒超时；字面关键字匹配、原始基线正文精确比较和 TSV 汇总。它们是筛选线索，不自动宣告漏洞。
10. **中英文界面、文档和文件导出**：EN / ZH 切换，英文直达 `?lang=en`；TXT / TSV 可选导出；执行不需要下载脚本或载荷文件。

## 为什么仍不能称为“完整替代”

1. **任意网站的在线扫描不能由这个页面独立完成。** 浏览器同源策略限制跨域读取；携带 Authorization 的请求通常需要 CORS 预检，目标服务器必须允许页面来源。`no-cors` 只能得到不透明响应，不能读取状态、响应头、正文，也不能自由携带所需请求头。此应用还刻意设置 CSP `connect-src 'none'`，遵循“不上传、不交互”的要求。可行方案已经实现：在用户本机终端执行内嵌 curl 循环。终端执行不等于页面独立扫描。
2. **原始 HTTP / TLS / 网络栈控制超出普通页面权限。** 页面不能随意设置 Host、Cookie、Content-Length 等受限请求头，不能关闭证书验证、指定任意本机代理、直接使用 TCP socket，也不能直接取得浏览器中目标站点的 HttpOnly Cookie。curl 能处理用户明确提供的命令参数，所以保留为终端执行环节。扩展、后端代理或本地服务可突破部分限制，但会改变“纯前端网页、无额外服务”的部署条件。
3. **服务器是否真正接受伪造 JWT，必须观察目标行为。** 载荷的构造或验签不能代替目标的密钥选择、算法白名单、身份解析和权限逻辑。200 可能是登录页、错误页或匿名公开接口；基线响应相同也可能只是统一错误。已实现关键字与正文比较，但不能据此对所有应用做可靠漏洞判定。后续可在终端侧实现用户定义的状态 / JSON 路径规则，仍需明确成功条件。
4. **自适应 Playbook 与跨请求会话逻辑尚未完整复刻。** 固定载荷、单字段 Fuzz、顺序重放、日志已经实现；登录、刷新 JWT、动态 CSRF、从上一个响应提取变量、发现成功后改变下一轮载荷等需要目标专用的状态机。JavaScript 本身可以表达这些流程，限制来自目标 CORS / 网络权限和本项目单条 curl 模板模型；可通过扩展终端命令或后端实现，不能宣称已经具备。没有一份对所有网站都有效的固定脚本。
5. **HMAC 字典检查可做，但无法承诺原生高速或穷举成功。** 当前 Worker 实现是真的检查，不是只生成候选载荷。浏览器的 CPU 调度、内存、标签页后台限流及 Web Crypto 每次调用开销影响吞吐；WASM / WebGPU 可以进一步优化，仍受设备与浏览器限制。强随机 secret 的搜索空间无法靠前端或 jwt_tool 穷举解决，使用 GPU / 原生计算也不会消除密码学难度。10,000 项上限是当前产品的资源边界，可继续扩展为流式文件批处理。
6. **远程 JKU / x5u / SSRF 与带外回调需要目标及可达基础设施。** 页面可以构造并签名这些 header，Pages 可以静态托管匹配公钥，但无法使目标主动信任它们，也不能替目标读取本地文件、执行 SQL 或回连指定地址。纯静态 Pages 不提供收集 DNS / HTTP 回调的常驻监听服务。可以接入用户自己的 OAST / 回调服务；本项目没有凭空生成这类服务。kid 路径、注入字符串也只在特定服务端实现下有意义。
7. **格式、算法和兼容性还有边界。** 本项目明确支持 compact JWS，不支持完整 JWE 解密 / 重加密、嵌套 JWT、分离载荷或所有 JSON Serialization 变体；这不等于 jwt_tool 必然支持这些全部格式。JWE 可以用前端 JS / WASM 和合适密钥实现，但它属于另一套 JOSE 处理链，不是 jwt_tool README 所列核心 JWS 功能缺口。本次没有为“完整替代”虚构其能力，也没有声称 Web Crypto 覆盖所有历史、非标准、弱算法和损坏 ASN.1 编码。当前 PEM 仅处理 PKCS#8 / SPKI，不自动转换加密私钥或任意证书链。
8. **日志可导出，不能无授权访问本机任意文件。** 已保存逐条请求结果和 TSV；页面没有 jwt_tool 的既有本机配置文件、历史日志目录或任意路径读取权限。文件选择器、IndexedDB 或 File System Access API 能支持新的授权导入 / 本地历史，但不能自动接管已有 CLI 的所有文件与运行环境。当前页面不持久化 Token 与密钥。

结论：纯前端能覆盖绝大多数离线 JWS 构造、签名、验签、字典和密钥工具功能；HTTP 重放已通过可复制终端命令完成。任意目标的网络访问、服务端行为判定、带外监听和应用专用自适应流程不能仅凭一个静态页面无条件完成。

## 依据

- jwt_tool 官方说明：<https://github.com/ticarpi/jwt_tool>
- jwt_tool 使用文档：<https://github.com/ticarpi/jwt_tool/wiki/Using-jwt_tool>
- 浏览器同源策略：<https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy>
- CORS：<https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS>
- Forbidden request headers：<https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_request_header>
- Web Crypto：<https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto>
