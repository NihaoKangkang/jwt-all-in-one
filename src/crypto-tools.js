import { b64url, bytes, encode, hmac, parseJwt, pemBytes, unbase64 } from './jwt.js';

export const ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
function config(alg) {
  if (!ALGORITHMS.includes(alg)) throw new Error('Unsupported signing algorithm.');
  const bits = Number(alg.slice(-3));
  const hash = `SHA-${bits}`;
  if (alg.startsWith('HS')) return { import: { name: 'HMAC', hash }, sign: { name: 'HMAC' }, hash };
  if (alg.startsWith('RS')) return { import: { name: 'RSASSA-PKCS1-v1_5', hash }, sign: { name: 'RSASSA-PKCS1-v1_5' } };
  if (alg.startsWith('PS')) return { import: { name: 'RSA-PSS', hash }, sign: { name: 'RSA-PSS', saltLength: bits / 8 } };
  if (alg.startsWith('ES')) return { import: { name: 'ECDSA', namedCurve: { 256: 'P-256', 384: 'P-384', 512: 'P-521' }[bits] }, sign: { name: 'ECDSA', hash } };
  return { import: { name: 'Ed25519' }, sign: { name: 'Ed25519' } };
}
function resolveJwk(material, header) {
  const parsed = JSON.parse(material);
  if (!parsed.keys) return parsed;
  const matches = parsed.keys.filter(key => (!header.kid || key.kid === header.kid) && (!key.alg || key.alg === header.alg));
  if (matches.length !== 1) throw new Error('JWKS must identify exactly one matching key (kid / alg).');
  return matches[0];
}
function isJwkMaterial(header, material, format = 'auto') {
  if (!['auto', 'raw', 'jwk'].includes(format)) throw new Error('Unsupported key input format.');
  // An HMAC secret is arbitrary text, including JSON. Only parse it as JWK on explicit opt-in.
  return format === 'jwk' || (format === 'auto' && !header.alg.startsWith('HS') && material.trim().startsWith('{'));
}
async function importMaterial(header, material, usage, extractable = false, format = 'auto') {
  const settings = config(header.alg);
  if (isJwkMaterial(header, material, format)) return crypto.subtle.importKey('jwk', resolveJwk(material, header), settings.import, extractable, [usage]);
  if (header.alg.startsWith('HS')) return crypto.subtle.importKey('raw', bytes(material), settings.import, extractable, [usage]);
  const type = usage === 'sign' ? 'PRIVATE' : 'PUBLIC';
  if (!material.includes(`-----BEGIN ${type} KEY-----`)) throw new Error(`Expected PKCS#8 PRIVATE KEY or SPKI PUBLIC KEY PEM, or JWK / JWKS (${type}).`);
  return crypto.subtle.importKey(usage === 'sign' ? 'pkcs8' : 'spki', pemBytes(material), settings.import, extractable, [usage]);
}
export async function signToken(header, payload, material, options = {}) {
  if (header.b64 === false || header.crit?.length) throw new Error('Custom signing does not accept b64=false or unimplemented crit extensions.');
  const settings = config(header.alg);
  const input = `${encode(header)}.${encode(payload)}`;
  if (header.alg.startsWith('HS') && !isJwkMaterial(header, material, options.format)) return `${input}.${await hmac(input, material, settings.hash)}`;
  const key = await importMaterial(header, material, 'sign', false, options.format);
  return `${input}.${b64url(await crypto.subtle.sign(settings.sign, key, bytes(input)))}`;
}
export async function verifyToken(token, material, options = {}) {
  const { header, payload, segments } = parseJwt(token);
  if (header.b64 === false || header.crit?.length) throw new Error('Verification does not accept b64=false or unimplemented crit extensions.');
  const settings = config(header.alg);
  const input = segments.slice(0, 2).join('.');
  let valid;
  if (header.alg.startsWith('HS') && !isJwkMaterial(header, material, options.format)) {
    const expected = unbase64(await hmac(input, material, settings.hash));
    const actual = unbase64(segments[2]);
    let difference = expected.length ^ actual.length;
    for (let i = 0; i < expected.length; i++) difference |= expected[i] ^ (actual[i] ?? 0);
    valid = difference === 0;
  } else {
    const key = await importMaterial(header, material, 'verify', false, options.format);
    valid = await crypto.subtle.verify(settings.sign, key, unbase64(segments[2]), bytes(input));
  }
  const now = Date.now() / 1000;
  return { valid, expired: typeof payload.exp === 'number' && payload.exp <= now, notYetValid: typeof payload.nbf === 'number' && payload.nbf > now,
    invalidTimeClaims: ['exp', 'nbf'].some(claim => Object.hasOwn(payload, claim) && (typeof payload[claim] !== 'number' || !Number.isFinite(payload[claim]))) };
}
function pem(label, data) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  return `-----BEGIN ${label} KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END ${label} KEY-----\n`;
}
export async function generateKeyPair(alg = 'RS256') {
  const settings = config(alg);
  if (alg.startsWith('HS')) throw new Error('Choose an asymmetric key algorithm.');
  const parameters = alg.startsWith('RS') || alg.startsWith('PS')
    ? { ...settings.import, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }
    : settings.import;
  const pair = await crypto.subtle.generateKey(parameters, true, ['sign', 'verify']);
  const jwk = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), alg, kid: `jwt-lab-${crypto.randomUUID()}`, use: 'sig' };
  return {
    publicPem: pem('PUBLIC', await crypto.subtle.exportKey('spki', pair.publicKey)),
    privatePem: pem('PRIVATE', await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
    jwks: { keys: [jwk] },
  };
}
export async function publicKeyFromJwks(material, header) {
  if (header.alg.startsWith('HS')) throw new Error('HMAC does not have a public key.');
  const key = await importMaterial(header, material, 'verify', true);
  return pem('PUBLIC', await crypto.subtle.exportKey('spki', key));
}
export async function checkDictionary(token, words, progress = () => {}) {
  const { header } = parseJwt(token);
  if (!header.alg.startsWith('HS')) throw new Error('Dictionary checking supports HS256 / HS384 / HS512 only.');
  const candidates = [...new Set(['', ...words])];
  if (candidates.length > 10001) throw new Error('Dictionary is limited to 10,000 supplied candidates.');
  for (let index = 0; index < candidates.length; index++) {
    if ((await verifyToken(token, candidates[index], { format: 'raw' })).valid) return { found: true, secret: candidates[index], checked: index + 1, total: candidates.length };
    if (index % 50 === 0) progress({ checked: index + 1, total: candidates.length });
  }
  return { found: false, checked: candidates.length, total: candidates.length };
}
