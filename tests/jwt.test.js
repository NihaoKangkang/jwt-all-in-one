import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { assemble, b64url, bytes, encode, hmac, parseJwt, signHmac, unbase64 } from '../src/jwt.js';
import { CATEGORIES, generatePayloads } from '../src/payloads.js';
import { TEST_KEYS } from '../src/keys.js';

const original = assemble({ alg: 'RS256', typ: 'JWT', kid: 'original' }, { sub: '用户', role: 'user', exp: 1800000000 }, b64url('original-signature'));
test('UTF-8 decode, structure validation, and JWE rejection', () => {
  assert.equal(parseJwt(original).payload.sub, '用户');
  for (const token of ['a.b', 'a.b.c.d.e', '!!..', `${encode([])}.${encode({})}.`, `${encode({})}.${encode({})}.`, `${encode({ alg: 'RS256' })}.${encode(null)}.`]) assert.throws(() => parseJwt(token));
});
test('empty and nonempty HMAC match independent Node crypto for every hash', async () => {
  for (const hash of ['SHA-256', 'SHA-384', 'SHA-512']) for (const key of ['', 'secret', '密钥', 'x'.repeat(200)]) {
    const expected = createHmac(hash.toLowerCase().replace('-', ''), key).update('header.payload').digest('base64url');
    assert.equal(await hmac('header.payload', key, hash), expected);
  }
});
test('fixture PEMs, module JWKs, JWKS file, and certificate describe the same keys', () => {
  const jwks = JSON.parse(readFileSync(new URL('../keys/jwks.json', import.meta.url)));
  for (const key of TEST_KEYS) {
    assert.equal(readFileSync(new URL(`../keys/${key.id}-private.pem`, import.meta.url), 'utf8'), key.privatePem);
    assert.equal(readFileSync(new URL(`../keys/${key.id}-public.pem`, import.meta.url), 'utf8'), key.publicPem);
    assert.deepEqual(jwks.keys.find(jwk => jwk.kid === key.jwk.kid), key.jwk);
    assert.equal(createPublicKey({ key: key.jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' }), key.publicPem);
  }
  const cert = new X509Certificate(readFileSync(new URL('../keys/rsa-a-certificate.pem', import.meta.url)));
  assert.equal(cert.publicKey.export({ type: 'spki', format: 'pem' }), TEST_KEYS[0].publicPem);
});
test('all embedded JWK injection signatures verify independently', async () => {
  const { rows } = await generatePayloads(original, { categories: ['jwk'] });
  assert.equal(rows.length, 3);
  for (const row of rows) {
    const { header, segments } = parseJwt(row.token);
    const publicKey = createPublicKey({ key: header.jwk, format: 'jwk' });
    assert(verify('sha256', bytes(segments.slice(0, 2).join('.')), { key: publicKey, dsaEncoding: 'ieee-p1363' }, unbase64(segments[2])));
    assert(!('d' in header.jwk));
  }
});
test('remote-key signatures match selected public keys and x5u certificate', async () => {
  const { rows } = await generatePayloads(original, { categories: ['jku'], jwksUrl: 'https://example.test/keys/jwks.json', certificateUrl: 'https://example.test/keys/rsa-a-certificate.pem' });
  assert.equal(rows.length, 3);
  for (const row of rows) {
    const { header, segments } = parseJwt(row.token);
    const key = TEST_KEYS.find(key => key.jwk.kid === header.kid);
    assert(verify('sha256', bytes(segments.slice(0, 2).join('.')), key.publicPem, unbase64(segments[2])));
  }
});
test('RS/HS confusion requires actual public key and signs with its representations', async () => {
  const skipped = await generatePayloads(original, { categories: ['confusion'] });
  assert.equal(skipped.rows.length, 0); assert.equal(skipped.warnings.length, 1);
  const { rows } = await generatePayloads(original, { categories: ['confusion'], targetPublicKey: TEST_KEYS[0].publicPem });
  assert.equal(rows.length, 12);
  const first = rows[0].token.split('.');
  assert.equal(first[2], createHmac('sha256', TEST_KEYS[0].publicPem).update(first.slice(0, 2).join('.')).digest('base64url'));
  await assert.rejects(generatePayloads(original, { categories: ['confusion'], targetPublicKey: TEST_KEYS[2].publicPem }));
});
test('category switches exclude payloads, including custom combinations', async () => {
  for (const category of CATEGORIES) {
    const { rows } = await generatePayloads(original, { categories: [category.id], customPayload: '{"role":"admin"}' });
    assert(rows.every(row => row.category === category.id));
  }
  const categories = CATEGORIES.map(c => c.id).filter(id => id !== 'none');
  const { rows } = await generatePayloads(original, { categories, customPayload: '{"role":"admin"}' });
  assert(!rows.some(row => row.category === 'none'));
  assert(!rows.some(row => row.category === 'custom' && parseJwt(row.token).header.alg === 'none'));
  assert(!rows.some(row => row.label.includes('重复 alg')));
});
test('claim tests preserve original signature and mutate only one claim', async () => {
  const { rows } = await generatePayloads(original, { categories: ['claims'] });
  for (const row of rows) assert.equal(row.token.split('.')[2], original.split('.')[2]);
  const role = rows.find(row => row.label.startsWith('role'));
  assert.deepEqual(parseJwt(role.token).payload, { ...parseJwt(original).payload, role: 'admin' });
});
test('ECDSA zero signatures use exact JOSE curve widths', async () => {
  const { rows } = await generatePayloads(original, { categories: ['ecdsa'] });
  assert.deepEqual(rows.filter(row => row.label.includes('JOSE')).map(row => unbase64(row.token.split('.')[2]).length), [64, 96, 132]);
});
test('invalid custom JSON and URLs fail with actionable errors', async () => {
  await assert.rejects(generatePayloads(original, { categories: ['custom'], customPayload: 'bad' }), /JSON/);
  await assert.rejects(generatePayloads(original, { categories: ['custom'], customPayload: '[]' }), /对象/);
  await assert.rejects(generatePayloads(original, { categories: ['jku'], jwksUrl: 'javascript:alert(1)' }), /HTTP/);
});
test('baseline remains byte-identical, generated ids unique, exports contain no newline tokens', async () => {
  const { rows } = await generatePayloads(original);
  assert.equal(rows[0].token, original);
  assert.equal(new Set(rows.map(row => row.id)).size, rows.length);
  assert(rows.every(row => /^[A-Za-z0-9_.=+/-]+$/.test(row.token)));
});
