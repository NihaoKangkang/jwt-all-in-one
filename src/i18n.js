// Translate interface text only; never transform JWTs, JSON editors, keys, or curl input.
const dictionary = {
  '时间声明无效': 'Invalid time claims',
  '自定义字段 Fuzz': 'Custom field fuzzing', '逐行替换 Header / Payload 字段，组合已启用的签名方式。': 'Replace header / payload fields line by line, combining enabled signature methods.',
  'Fuzz 字段位置': 'Fuzz field location', 'Fuzz 字段路径': 'Fuzz field path', '例如 role 或 user.role': 'For example role or user.role', 'Fuzz 值': 'Fuzz values', '每行 JSON 值或字符串，最多 50 项': 'One JSON value or string per line, up to 50',
  'JWT All in One · 安全测试工作台': 'JWT All in One · Security Workbench',
  '纯前端 JWT 安全测试工作台：生成测试载荷、导出文件与批量 curl 脚本。': 'Browser-only JWT security workbench: create payloads and copy a complete curl test command.',
  '一个 JWT，多种测试可能': 'One JWT. Many test possibilities',
  '解码、构造、导出。把重复的准备工作，交给浏览器。': 'Decode, mutate, and test. Let your browser handle the repetitive work.',
  '你的 Token 留在浏览器。': 'Your token stays in your browser.',
  '无后端，无上传，无追踪。': 'No backend. No uploads. No tracking.',
  '100% 浏览器本地运行': '100% local processing',
  '仅用于你拥有权限的安全测试': 'For authorized security testing',
  'JWT 测试工作台': 'JWT workbench', '测试工作台': 'Workbench', '载荷配置': 'Payload options', '导出与执行': 'Export & run',
  '工具 /': 'Tools /', '输入凭证': 'Input token', '选择测试': 'Choose tests', '导出并执行': 'Copy & run',
  '输入 JWT': 'Input JWT', '载入示例': 'Load example', '原始 Token': 'Original token', '复制命令必填': 'Required for command', '必填': 'Required',
  '支持三段式 JWS · 自动解析 Header 与 Payload': 'Three-part JWS · automatic header and payload decoding',
  '等待有效 JWT…': 'Waiting for a valid JWT…', '等待输入…': 'Waiting for input…', '结构可解码': 'Structure decoded', '签名尚未验证': 'Signature not verified',
  '完整 curl 请求': 'Complete curl request',
  '粘贴从浏览器复制的 curl，将 JWT 替换为': 'Paste a curl request from your browser. Replace the JWT with',
  '。支持 Header、Cookie、URL 和请求体。': '. Supported in headers, cookies, URLs, and request bodies.',
  '引号中的占位符也会正确替换；支持单条 Bash / POSIX 风格 curl。': 'Quoted placeholders are supported. Use a single Bash / POSIX curl command.',
  '测试载荷': 'Test payloads', '全选': 'Select all', '清空': 'Clear',
  '默认启用所有类别。取消勾选后，不生成该类别载荷。': 'All categories are enabled by default. Uncheck a category to exclude its payloads.',
  '原始请求基线': 'Original baseline', '保留原始 JWT，用响应对照每个测试。': 'Keep the original JWT to compare responses with each test.',
  'none / None / NONE / nOnE，含尾点与无尾点。': 'none / None / NONE / nOnE, with and without a trailing dot.',
  '空签名与签名变形': 'Signature mutations', '缺失、截断、位翻转、随机签名及多余分段。': 'Missing, truncated, modified, random signatures, and extra segments.',
  '空密钥与常见弱密钥': 'Empty & weak HMAC keys', 'HS256 / 384 / 512 空密钥与少量测试字典重新签名。': 'Re-sign using empty HS256 / 384 / 512 keys and a small candidate list.',
  'RSA → HMAC 算法混淆': 'RSA → HMAC confusion', '使用目标公钥的 PEM / DER 等表示作为 HMAC secret。需要输入目标公钥。': 'Use target PEM / DER public-key representations as HMAC secrets. Requires the actual target public key.',
  '内嵌 JWK 公钥注入': 'Embedded JWK injection', '两对 RSA 与一对 EC 测试密钥，嵌入公钥并正确签名。': 'Embed and correctly sign with two RSA and one EC public test key.',
  'JKU / x5u 远程密钥': 'JKU / x5u remote keys', 'JKU 指向公开 JWKS；x5u 指向公开测试证书。': 'Point JKU to a public JWKS and x5u to the matching test certificate.',
  'kid 路径与注入': 'kid paths & injection', '空值、路径遍历、空文件及 SQL 字符串，含匹配空 secret 签名。': 'Empty values, traversal, empty files, and SQL strings, including empty-secret signatures.',
  'Claims 与时间篡改': 'Claims & timestamps', '角色、主体、issuer / audience、过期时间等单项变更；保留原签名。': 'Change roles, subject, issuer, audience, and timestamps, retaining the original signature.',
  'Header 与解析差异': 'Header & parser variations', '重复 alg、未知 crit、typ、b64、Base64 填充等变形。': 'Duplicate alg, unknown crit, typ, b64, and Base64 padding variations.',
  'ECDSA 零值签名': 'ECDSA zero signatures', 'ES256 / 384 / 512 的 JOSE 全零签名与 DER 变体。': 'All-zero JOSE signatures and DER variations for ES256 / 384 / 512.',
  '自定义 Payload': 'Custom payload', '使用编辑后的 JSON，组合 none、JWK 与空密钥重新签名。': 'Edit JSON, combine enabled none / JWK / empty-key tests, or sign with your own key.',
  '高级配置': 'Advanced options', '目标公钥 / 自定义内容': 'Target key / custom content',
  '目标 RSA 公钥': 'Target RSA public key', 'RS/HS 混淆必须使用目标公钥；不填写则跳过该项。': 'RS/HS confusion requires the actual target public key. Skipped when blank.',
  '公开 JWKS URL': 'Public JWKS URL', '公开 X.509 证书 URL': 'Public X.509 certificate URL',
  '默认指向本项目公开测试密钥。自定义 URL 需托管相同公钥 / 证书。': 'Defaults to this project’s public test keys. Custom URLs must host matching keys / certificates.',
  '附加弱密钥字典': 'Additional weak-key candidates', '每行一个，最多 100 项': 'One per line, up to 100',
  '自定义声明可组合已勾选的 none / HMAC / JWK 测试。': 'Custom claims combine with enabled none / HMAC / JWK categories.',
  '自定义 Header JSON': 'Custom header JSON', '留空使用原始 Header': 'Blank uses the original header',
  '使用下面的密钥对自定义内容签名': 'Sign custom content with the key below', '签名密钥': 'Signing key',
  'HS / RS / PS / ES / EdDSA。勾选后，空 HMAC 密钥也会用于签名。密钥只留在页面内存。': 'HS / RS / PS / ES / EdDSA. When enabled, a blank HMAC key means the empty secret. Keys stay in page memory.',
  '请求间隔（秒）': 'Request delay (seconds)', '超时（秒）': 'Timeout (seconds)', '响应关键字': 'Response canary', '可选，按原文匹配': 'Optional literal substring',
  '个类别已选择': 'categories selected', '生成测试载荷': 'Generate payloads', '正在生成…': 'Generating…',
  '生成结果': 'Generated results', '等待生成': 'Waiting', '生成完成': 'Ready', '无可生成载荷': 'No payloads available', '覆盖类别': 'Categories', '网络请求': 'Network requests',
  '载荷预览': 'Payload preview', '搜索类别或载荷…': 'Search categories or payloads…', '搜索载荷': 'Search payloads',
  '你的测试，从一个 Token 开始': 'Your test starts with one token', '输入 JWT，选择测试类别': 'Enter a JWT and select test categories',
  '点击「生成测试载荷」即可查看结果。': 'Click Generate payloads to see the results.', '输入 JWT，选择测试类别，生成后在这里查看。': 'Enter a JWT, choose tests, and generate to preview the results here.',
  '一键复制完整命令，直接粘贴到终端执行。已内嵌全部载荷，不需要下载任何文件。': 'Copy the complete command and paste it into your terminal. All payloads are embedded. No files to download.',
  '复制完整执行命令': 'Copy complete test command', '复制全部 JWT': 'Copy all JWTs',
  '生成后，点击上方按钮复制完整命令': 'Generate payloads, then copy the complete command above',
  '串行执行 · 默认间隔 0.2 秒 · 默认超时 30 秒': 'Sequential requests · default delay 0.2 s · default timeout 30 s',
  '逐条输出 JWT、HTTP 状态、响应头和正文，并保存 summary.tsv、关键字匹配与基线正文对比。': 'Print each JWT, status, headers, and body. Save summary.tsv with canary matches and baseline body comparisons.',
  '载荷说明.tsv': 'payload-manifest.tsv', '预览可直接执行的完整命令': 'Preview the complete executable command',
  '生成载荷并填写 curl 后，在这里预览命令。': 'Generate payloads and supply curl to preview the command here.', '复制完整命令': 'Copy complete command',
  '结果需要结合业务判断': 'Interpret results in application context',
  'JWT 结构可解码不等于签名有效；返回 200 也不等于绕过。与原始请求对照，确认身份、权限和实际业务响应。公开测试私钥仅供实验。': 'A decodable JWT does not imply a valid signature. HTTP 200 does not establish a bypass. Compare identity, permissions, and business responses with the baseline. Public private keys are for testing only.',
  '本地构造，明确验证。': 'Build locally. Verify explicitly.', '公开测试密钥': 'Public test keys', 'GitHub 仓库': 'GitHub repository',
  '本地密码工具': 'Local crypto tools', '验证原始 JWT 签名': 'Verify the original JWT signature', '验证密钥': 'Verification key',
  '仅检查签名与 exp / nbf；不验证业务权限或 issuer / audience。空输入可检查空 HMAC 密钥。': 'Checks signature and exp / nbf only, not authorization or issuer / audience. Blank input checks the empty HMAC secret.',
  '本地验签': 'Verify locally', '导出公钥 PEM': 'Export public PEM', 'HMAC 离线字典检查': 'Offline HMAC dictionary check',
  '候选密钥': 'Candidate secrets', '每行一个，最多 10,000 项': 'One per line, up to 10,000',
  '在 Web Worker 内检查原始签名，可随时取消；总会额外检查空密钥。此处不生成额外请求。': 'Check the original signature in a cancellable Web Worker. Always tests the empty secret too. No target requests.',
  '检查字典': 'Check dictionary', '取消检查': 'Cancel check', '生成本地密钥对': 'Generate a local key pair', '密钥算法': 'Key algorithm', '生成密钥对': 'Generate key pair',
  '已复制到剪贴板': 'Copied to clipboard', '复制失败，请手动选择文本复制': 'Clipboard unavailable. Select and copy the preview manually.',
  '输入或配置已更新，请重新生成载荷。': 'Inputs changed. Generate payloads again.', '没有匹配的载荷。': 'No matching payloads.', '复制 JWT': 'Copy JWT',
  '示例已载入；请换成你的授权测试请求': 'Example loaded. Replace it with your authorized test request.',
  '请至少选择一个测试类别。': 'Select at least one test category.', '此浏览器环境不支持 Web Crypto，请使用 HTTPS 或 localhost。': 'Web Crypto is unavailable. Use HTTPS or localhost.',
  '载荷已生成；命令尚未生成：': 'Payloads ready; command unavailable: ', '已生成 ': 'Generated ', ' 条测试载荷': ' payloads',
  '签名有效': 'Signature valid', '签名无效': 'Signature invalid', '已过期': 'Expired', '尚未生效': 'Not yet valid', '时间范围有效': 'Time range valid',
  '正在检查…': 'Checking…', '已检查 ': 'Checked ', '未找到匹配密钥': 'No matching secret found', '找到密钥：': 'Matching secret: ', '检查已取消': 'Check cancelled',
  '正在生成密钥…': 'Generating keys…', '密钥对已生成，仅保存在页面内存。': 'Key pair generated in page memory only.',
  '原始 JWT': 'Original JWT', '原始响应是比较基线；HTTP 200 本身不代表漏洞。': 'Compare against the original response. HTTP 200 alone does not prove a vulnerability.',
  '原签名通常失效，用于检查是否忽略签名或产生异常。': 'The original signature is normally invalid; checks whether verification is ignored or errors occur.',
  '保留原签名：用于检测服务是否校验完整性。': 'Original signature retained to test whether the service checks integrity.',
  '故意使用非 JOSE DER 格式，检测特定实现的兼容行为。': 'Intentionally non-JOSE DER encoding to test implementation-specific behavior.',
  '已跳过 RS/HS 混淆：需要目标服务实际使用的 RSA 公钥。仓库测试公钥不能代替目标公钥。': 'Skipped RS/HS confusion: supply the target’s actual RSA public key. Repository test keys cannot replace it.',
  '已跳过远程密钥：请配置公开 JWKS / 证书地址。': 'Skipped remote keys: configure a public JWKS / certificate URL.',
  '已跳过自定义 Payload：尚未填写 JSON。': 'Skipped custom payload: no JSON supplied.',
  '目标公钥必须是有效的 RSA SPKI PEM（BEGIN PUBLIC KEY）。': 'Target key must be a valid RSA SPKI PEM (BEGIN PUBLIC KEY).',
  '远程密钥地址必须是完整 HTTP(S) URL。': 'Remote key URL must be a complete HTTP(S) URL.', '远程密钥地址只支持 HTTP(S)。': 'Remote key URLs must use HTTP(S).',
  '弱密钥字典最多支持 100 项。': 'Payload generation supports up to 100 weak-key candidates.', '自定义 Payload JSON 无效。': 'Custom payload JSON is invalid.', '自定义 Payload 必须是 JSON 对象。': 'Custom payload must be a JSON object.',
  '请输入三段式 JWS（header.payload.signature）。暂不支持五段式 JWE。': 'Enter a three-part JWS (header.payload.signature). Five-part JWE is not supported.',
  'JWT 含有非法 Base64URL 字符。': 'JWT contains invalid Base64URL characters.', 'JWT 的 header/payload 必须是有效 UTF-8 JSON 对象，header 需要 alg。': 'JWT header and payload must be UTF-8 JSON objects; header needs alg.',
  '请输入完整 curl 命令，并用 $JWT_HERE 标记 JWT。': 'Enter a complete curl command with the $JWT_HERE placeholder.',
  'curl 命令末尾存在未完成的转义。': 'Incomplete escape at the end of curl.', '多行 curl 请使用反斜杠续行；不支持多条命令。': 'Use backslash continuations for multiline curl. Multiple commands are unsupported.',
  '仅支持单条 curl 命令；请移除管道、重定向、命令替换及 shell 表达式。': 'Use one curl command. Remove pipes, redirects, command substitutions, and shell expressions.',
  'curl 命令引号未闭合。': 'Unclosed quote in curl.', '命令必须以 curl 开始。': 'The command must start with curl.', 'curl 命令缺少 $JWT_HERE 占位符。': 'curl is missing the $JWT_HERE placeholder.',
  '请移除 curl 的输出、配置文件、并发或 --next 选项；结果保存由批量脚本统一处理。': 'Remove curl output, configuration, parallel, and --next flags. The batch command controls output capture.',
  '除 $JWT_HERE 外不支持其他 shell 变量或命令替换，请填入实际值。': 'Replace other shell variables and command substitutions with literal values; only $JWT_HERE is supported.',
  'curl 命令含有不支持的控制字符。': 'curl contains unsupported control characters.', '请求间隔须为 0–60 秒，超时须为 1–300 秒。': 'Delay must be 0–60 seconds and timeout 1–300 seconds.',
  '空签名': 'empty signature', '无尾点': 'no trailing dot', '保留 alg': 'original alg', '缺失签名段': 'missing signature segment', '截断签名': 'truncated signature', '签名首字符变更': 'modified signature',
  '随机签名': 'random signature', '额外分段': 'extra segment', '空密钥': 'empty key', '无尾换行': 'no final newline', '内嵌公钥': 'embedded public key', '测试证书': 'test certificate',
  '原签名': 'original signature', '删除 ': 'Remove ', '重复 alg': 'duplicate alg', '后置': 'last', '前置': 'first', '填充': 'padding', '标准 Base64 字符': 'standard Base64 characters', '自定义': 'custom',
  '。': '.',
};
const entries = Object.entries(dictionary).sort((a, b) => b[0].length - a[0].length);
export function translate(value, lang = 'en') {
  if (lang !== 'en') return String(value);
  let result = String(value);
  for (const [source, target] of entries) result = result.replaceAll(source, target);
  return result;
}
export let language = typeof location !== 'undefined' && new URLSearchParams(location.search).get('lang') === 'en' ? 'en' : 'zh';
const originalText = new WeakMap(), originalAttributes = new WeakMap();
const descriptionText = typeof document !== 'undefined' ? document.querySelector('meta[name="description"]')?.content : '';
export function localizeDom() {
  document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
  document.querySelector('.brand').setAttribute('href', language === 'en' ? './?lang=en' : './');
  document.title = translate('JWT All in One · 安全测试工作台', language);
  const description = document.querySelector('meta[name="description"]');
  if (description && descriptionText) description.content = translate(descriptionText, language);
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (node.parentElement.closest('pre,textarea,code,script,style,#language')) continue;
    if (!originalText.has(node)) originalText.set(node, node.nodeValue);
    const value = translate(originalText.get(node), language);
    if (node.nodeValue !== value) node.nodeValue = value;
  }
  for (const element of document.querySelectorAll('[placeholder],[aria-label]')) {
    if (!originalAttributes.has(element)) originalAttributes.set(element, { placeholder: element.getAttribute('placeholder'), 'aria-label': element.getAttribute('aria-label') });
    for (const [attribute, value] of Object.entries(originalAttributes.get(element))) if (value !== null) element.setAttribute(attribute, translate(value, language));
  }
  const button = document.getElementById('language');
  const label = language === 'en' ? 'ZH' : 'EN';
  if (button.textContent !== label) button.textContent = label;
  button.setAttribute('aria-label', language === 'en' ? 'Switch to Chinese' : 'Switch to English');
}
export function switchLanguage() {
  language = language === 'en' ? 'zh' : 'en';
  const url = new URL(location.href);
  url.searchParams.set('lang', language);
  history.replaceState(null, '', url);
  localizeDom();
}
export function observeTranslations() {
  localizeDom();
  new MutationObserver(localizeDom).observe(document.body, { childList: true, subtree: true });
}
