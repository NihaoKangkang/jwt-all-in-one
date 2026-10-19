import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { generateCommand, manifestTsv, parseCurl } from '../src/curl.js';
const exec = promisify(execFile);
test('curl parser handles multiline, quote concatenation, escaped quotes and repeated placeholders', () => {
  const args = parseCurl("curl 'https://example.test?q=$JWT_HERE' \\\n  -H 'Authorization: Bearer $JWT_HERE' --data-raw '{\"jwt\":\"$JWT_HERE\",\"name\":\"O'\\''Brien\"}'");
  assert.deepEqual(args, ['https://example.test?q=$JWT_HERE', '-H', 'Authorization: Bearer $JWT_HERE', '--data-raw', '{"jwt":"$JWT_HERE","name":"O\'Brien"}']);
  assert.deepEqual(parseCurl('curl https://example.test -H "X: \\$JWT_HERE"'), ['https://example.test', '-H', 'X: $JWT_HERE']);
});
test('curl parser rejects command chains, unresolved variables, and output/config overrides', () => {
  for (const template of [
    'wget https://example.test/$JWT_HERE', 'curl https://example.test', "curl 'unclosed",
    'curl https://example.test/$JWT_HERE; rm -rf /', 'curl https://example.test/$JWT_HERE | sh',
    'curl https://example.test/$JWT_HERE\necho extra-command',
    'curl https://example.test/$JWT_HERE -K config', 'curl https://example.test/$JWT_HERE --next https://example.test',
    'curl https://example.test/$JWT_HERE -o out', 'curl https://example.test/$JWT_HERE -svoout',
    'curl https://example.test/$JWT_HERE -H "X: $SECRET"', 'curl https://example.test/$JWT_HERE -H "X: $(whoami)"',
  ]) assert.throws(() => parseCurl(template), template);
});
test('manifest sanitizes line separators in user-controlled labels', () => {
  const result = manifestTsv([{ id: 'JWT-0001', category: 'hmac', label: 'test\tlabel\nline', note: '', token: 'a.b.c' }]);
  assert.equal(result.split('\n').length, 3);
  assert.equal(result.split('\n')[1].split('\t').length, 5);
});
test('generated Bash runs a full for-loop against a local server and preserves request and response data', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'jwt-command-test-'));
  const received = [];
  const server = createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    received.push({ url: request.url, headers: request.headers, body });
    response.writeHead(received.length === 1 ? 200 : 401, { 'Content-Type': 'application/json', 'X-JWT-Lab': 'test' });
    response.end(JSON.stringify({ jwt: request.headers.authorization, body, literal: '$HOME; $(false)' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    const rows = [{ id: 'JWT-0001', category: 'none', label: "a 'quoted' label", token: 'abc.def.' }, { id: 'JWT-0002', category: 'baseline', label: 'baseline', token: 'abc.def.ghi' }];
    const template = `curl 'http://127.0.0.1:${address.port}/echo?jwt=$JWT_HERE' -X POST -H 'Authorization: Bearer $JWT_HERE' -b 'jwt=$JWT_HERE; theme=dark' --data-raw '{"jwt":"$JWT_HERE","name":"O'\\''Brien"}'`;
    const script = generateCommand(template, rows, { canary: '$HOME; $(false)', delay: 0 });
    await writeFile(join(directory, 'command.sh'), script);
    await exec('bash', ['-n', 'command.sh'], { cwd: directory });
    const { stdout } = await exec('bash', ['command.sh'], { cwd: directory });
    assert.equal(received.length, 2);
    for (let index = 0; index < rows.length; index++) {
      assert.equal(received[index].headers.authorization, `Bearer ${rows[index].token}`);
      assert.equal(received[index].headers.cookie, `jwt=${rows[index].token}; theme=dark`);
      assert.equal(received[index].url, `/echo?jwt=${rows[index].token}`);
      assert.deepEqual(JSON.parse(received[index].body), { jwt: rows[index].token, name: "O'Brien" });
    }
    assert.match(stdout, /HTTP: 200/); assert.match(stdout, /HTTP: 401/); assert.match(stdout, /response body/);
    const resultDir = join(directory, (await readdir(directory)).find(name => name.startsWith('jwt-results.')));
    const summary = await readFile(join(resultDir, 'summary.tsv'), 'utf8');
    assert.match(summary, /yes\t/); assert.match(summary, /200\t0/); assert.match(summary, /401\t0/);
    assert.equal(await readFile(join(resultDir, '0002.jwt.txt'), 'utf8'), rows[1].token + '\n');
    assert.match(await readFile(join(resultDir, '0001.headers'), 'utf8'), /X-JWT-Lab: test/i);
    assert.equal(JSON.parse(await readFile(join(resultDir, '0001.body'), 'utf8')).literal, '$HOME; $(false)');
  } finally { await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); }
});
test('curl connection failures are recorded and later payloads still execute', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'jwt-failure-test-'));
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  try {
    const rows = ['a.b.c', 'a.b.'].map((token, i) => ({ id: `JWT-${i}`, category: 'test', label: 'test', token }));
    await writeFile(join(directory, 'command.sh'), generateCommand(`curl http://127.0.0.1:${port}/$JWT_HERE`, rows));
    const { stdout } = await exec('bash', ['command.sh'], { cwd: directory });
    assert.equal((stdout.match(/curl exit: 7/g) || []).length, 2);
    const resultDir = join(directory, (await readdir(directory)).find(name => name.startsWith('jwt-results.')));
    assert.equal((await readFile(join(resultDir, 'summary.tsv'), 'utf8')).trim().split('\n').length, 3);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
