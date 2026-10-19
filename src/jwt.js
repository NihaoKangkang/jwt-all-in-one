const encoder = new TextEncoder();
export const bytes = value => encoder.encode(value);
export function b64url(value) {
  const data = typeof value === 'string' ? bytes(value) : new Uint8Array(value);
  let binary = '';
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
export function unbase64(value) {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
export const encode = value => b64url(JSON.stringify(value));
export const assemble = (header, payload, signature = '') => `${encode(header)}.${encode(payload)}.${signature}`;
export function parseJwt(input) {
  const token = input.trim();
  const segments = token.split('.');
  if (segments.length !== 3) throw new Error('请输入三段式 JWS（header.payload.signature）。暂不支持五段式 JWE。');
  if (segments.some(segment => !/^[A-Za-z0-9_-]*={0,2}$/.test(segment))) throw new Error('JWT 含有非法 Base64URL 字符。');
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const header = JSON.parse(decoder.decode(unbase64(segments[0])));
    const payload = JSON.parse(decoder.decode(unbase64(segments[1])));
    if (!header || Array.isArray(header) || typeof header !== 'object' || typeof header.alg !== 'string') throw new Error();
    if (!payload || Array.isArray(payload) || typeof payload !== 'object') throw new Error();
    unbase64(segments[2]);
    return { token, segments, header, payload };
  } catch { throw new Error('JWT 的 header/payload 必须是有效 UTF-8 JSON 对象，header 需要 alg。'); }
}
export function pemBytes(pem) {
  return unbase64(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''));
}
// Manual RFC 2104 HMAC also supports the zero-length key rejected by SubtleCrypto.importKey.
export async function hmac(data, key, hash = 'SHA-256') {
  const block = hash === 'SHA-256' ? 64 : 128;
  let secret = typeof key === 'string' ? bytes(key) : key;
  if (secret.length > block) secret = new Uint8Array(await crypto.subtle.digest(hash, secret));
  const inner = new Uint8Array(block + bytes(data).length);
  const outer = new Uint8Array(block + Number(hash.split('-')[1]) / 8);
  for (let i = 0; i < block; i++) {
    inner[i] = (secret[i] || 0) ^ 0x36;
    outer[i] = (secret[i] || 0) ^ 0x5c;
  }
  inner.set(bytes(data), block);
  outer.set(new Uint8Array(await crypto.subtle.digest(hash, inner)), block);
  return b64url(await crypto.subtle.digest(hash, outer));
}
export async function signHmac(header, payload, key, hash = 'SHA-256') {
  const input = `${encode(header)}.${encode(payload)}`;
  return `${input}.${await hmac(input, key, hash)}`;
}
export async function signKey(header, payload, pem) {
  const ec = header.alg === 'ES256';
  const algorithm = ec ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  const key = await crypto.subtle.importKey('pkcs8', pemBytes(pem), algorithm, false, ['sign']);
  const input = `${encode(header)}.${encode(payload)}`;
  const signature = await crypto.subtle.sign(ec ? { name: 'ECDSA', hash: 'SHA-256' } : algorithm, key, bytes(input));
  return `${input}.${b64url(signature)}`;
}
