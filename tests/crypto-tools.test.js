import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createHmac, createPublicKey, verify } from 'node:crypto';
import { ALGORITHMS, checkDictionary, generateKeyPair, publicKeyFromJwks, signToken, verifyToken } from '../src/crypto-tools.js';
import { assemble, bytes, parseJwt, unbase64 } from '../src/jwt.js';
import { TEST_KEYS } from '../src/keys.js';
import { generatePayloads } from '../src/payloads.js';
import { translate } from '../src/i18n.js';

test('all 13 signing algorithms independently verify with Node crypto, including PSS and P-521', async () => {
  const extra = {};
  for (const alg of ['ES384', 'ES512', 'EdDSA']) extra[alg] = await generateKeyPair(alg);
  for (const alg of ALGORITHMS) {
    const key = alg.startsWith('HS') ? { privatePem: 'known-secret', publicPem: 'known-secret' } : extra[alg] || TEST_KEYS[alg === 'ES256' ? 2 : 0];
    const token = await signToken({ alg, typ: 'JWT' }, { sub: 'test', exp: 4102444800 }, key.privatePem);
    assert.equal((await verifyToken(token, key.publicPem)).valid, true, alg);
    const parts = token.split('.'), input = bytes(parts.slice(0, 2).join('.'));
    const hash = alg === 'EdDSA' ? null : `sha${alg.slice(-3)}`;
    if (alg.startsWith('HS')) assert.equal(parts[2], createHmac(hash, key.publicPem).update(input).digest('base64url'));
    else {
      const options = { key: key.publicPem, dsaEncoding: 'ieee-p1363' };
      if (alg.startsWith('PS')) Object.assign(options, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(alg.slice(-3)) / 8 });
      assert(verify(hash, input, options, unbase64(parts[2])), alg);
    }
    const { header, payload, segments } = parseJwt(token);
    assert.equal((await verifyToken(assemble(header, { ...payload, sub: 'tampered' }, segments[2]), key.publicPem)).valid, false, alg);
  }
});
test('JWK/JWKS verification selects keys by kid and exports matching public PEM', async () => {
  const key = TEST_KEYS[0];
  const token = await signToken({ alg: 'RS256', kid: key.jwk.kid }, { sub: 'test' }, key.privatePem);
  const material = JSON.stringify({ keys: TEST_KEYS.map(key => key.jwk) });
  assert((await verifyToken(token, material)).valid);
  assert.equal(await publicKeyFromJwks(material, parseJwt(token).header), key.publicPem);
  await assert.rejects(verifyToken(token, JSON.stringify({ keys: [] })), /matching key/);
});
test('key generation exports interoperable SPKI, PKCS8 and public-only JWKS', async () => {
  const pair = await generateKeyPair('RS256');
  const jwk = pair.jwks.keys[0];
  assert(!('d' in jwk));
  assert.equal(createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'pem', type: 'spki' }), pair.publicPem);
  const token = await signToken({ alg: 'RS256', kid: jwk.kid }, { sub: 'test' }, pair.privatePem);
  assert((await verifyToken(token, JSON.stringify(pair.jwks))).valid);
});
test('offline dictionary finds actual original signing secret, empty key, and no-match cases', async () => {
  for (const alg of ['HS256', 'HS384', 'HS512']) {
    const token = await signToken({ alg }, { sub: 'test' }, 'unique-secret');
    const found = await checkDictionary(token, ['wrong', 'unique-secret', 'unused']);
    assert.equal(found.secret, 'unique-secret'); assert.equal(found.checked, 3);
    assert.equal((await checkDictionary(token, ['wrong'])).found, false);
    const emptyToken = await signToken({ alg }, {}, '');
    assert.equal((await checkDictionary(emptyToken, [])).secret, '');
  }
  await assert.rejects(checkDictionary(assemble({ alg: 'RS256' }, {}, ''), []), /HS256/);
});
test('JSON-looking dictionary entries are always literal HMAC secrets, not JWK objects', async () => {
  const octJwk = JSON.stringify({ kty: 'oct', k: 'dW5pcXVlLXNlY3JldA', alg: 'HS256' });
  for (const alg of ['HS256', 'HS384', 'HS512']) {
    for (const secret of ['{broken', '{"secret":"literal-json"}', octJwk]) {
      const token = await signToken({ alg }, {}, secret);
      assert.equal((await verifyToken(token, secret)).valid, true);
      assert.equal((await checkDictionary(token, ['{invalid-json', secret])).secret, secret);
    }
    const token = await signToken({ alg }, {}, 'unique-secret');
    const found = await checkDictionary(token, ['{invalid-json', octJwk, 'unique-secret']);
    assert.equal(found.secret, 'unique-secret');
    assert.equal(found.checked, 4);
  }
});
test('HMAC JWK input is supported only with explicit JWK format', async () => {
  const material = JSON.stringify({ kty: 'oct', k: 'dW5pcXVlLXNlY3JldA', alg: 'HS256' });
  const token = await signToken({ alg: 'HS256' }, {}, material, { format: 'jwk' });
  assert((await verifyToken(token, 'unique-secret')).valid);
  assert((await verifyToken(token, material, { format: 'jwk' })).valid);
  assert.equal((await verifyToken(token, material)).valid, false);
});
test('temporal checks distinguish expired and future nbf from signature validity', async () => {
  const token = await signToken({ alg: 'HS256' }, { exp: 0, nbf: 4102444800 }, 'key');
  assert.deepEqual(await verifyToken(token, 'key'), { valid: true, expired: true, notYetValid: true, invalidTimeClaims: false });
  assert((await verifyToken(await signToken({ alg: 'HS256' }, { exp: 'invalid' }, 'key'), 'key')).invalidTimeClaims);
  await assert.rejects(signToken({ alg: 'none' }, {}, ''), /Unsupported/);
  await assert.rejects(signToken({ alg: 'HS256', crit: ['custom'] }, {}, 'key'), /crit/);
});
test('custom Header and Payload are actually signed with supplied material', async () => {
  const input = assemble({ alg: 'RS256' }, { sub: 'user' }, 'abc');
  const { rows } = await generatePayloads(input, { categories: ['custom'], customPayload: '{"sub":"admin"}', customHeader: '{"alg":"PS512"}', signingKey: TEST_KEYS[0].privatePem, signWithKey: true });
  const row = rows.find(row => row.label.includes('supplied'));
  assert.equal(parseJwt(row.token).header.alg, 'PS512');
  assert((await verifyToken(row.token, TEST_KEYS[0].publicPem)).valid);
});
test('field fuzzing supports nested JSON values and excludes disabled none combinations', async () => {
  const input = assemble({ alg: 'HS256' }, { user: { role: 'user' } }, 'abc');
  const { rows } = await generatePayloads(input, { categories: ['fuzz'], fuzzField: 'user.role', fuzzValues: '"admin"\nnull\ntrue\n0' });
  assert.equal(rows.length, 4);
  assert.deepEqual(rows.map(row => parseJwt(row.token).payload.user.role), ['admin', null, true, 0]);
  assert(rows.every(row => parseJwt(row.token).header.alg === 'HS256'));
  await assert.rejects(generatePayloads(input, { categories: ['fuzz'], fuzzField: '__proto__.polluted', fuzzValues: 'true' }), /unsupported/);
  assert.equal({}.polluted, undefined);
});
test('English translations cover core status and errors without translating token content', () => {
  assert.equal(translate('签名有效 · 时间范围有效'), 'Signature valid · Time range valid');
  assert.equal(translate('已生成 71 条测试载荷'), 'Generated 71 payloads');
  assert.equal(translate('空签名', 'zh'), '空签名');
});
