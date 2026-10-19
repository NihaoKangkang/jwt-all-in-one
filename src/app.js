import { encode, parseJwt, signHmac } from './jwt.js';
import { CATEGORIES, generatePayloads } from './payloads.js';
import { generateRunner, manifestTsv } from './curl.js';

const $ = id => document.getElementById(id);
let rows = [], script = '', version = 0, busy = false, toastTimer;
const fields = ['jwt', 'curl', 'public-key', 'jwks-url', 'certificate-url', 'secrets', 'custom-payload'];
const make = (tag, className, text) => {
  const element = document.createElement(tag);
  element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};
const selected = () => [...document.querySelectorAll('#categories input:checked')].map(input => input.value);
function toast(message) {
  $('toast').textContent = message; $('toast').hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3000);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('已复制到剪贴板'); }
  catch { toast('复制失败，请手动选择文本复制'); }
}
function download(name, text, type = 'text/plain;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name;
  document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
for (const category of CATEGORIES) {
  const label = make('label', 'category');
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox'; checkbox.value = category.id; checkbox.checked = true;
  const content = document.createElement('span');
  content.append(make('span', 'category-title', category.title), make('span', 'category-tag', category.tag), make('span', 'category-detail', category.detail));
  label.append(checkbox, content); $('categories').append(label);
  checkbox.addEventListener('change', invalidate);
}
// Bundled key material is imported as a module; generating payloads never fetches anything.
const publicBase = new URL('../keys/', import.meta.url);
$('jwks-url').value = new URL('jwks.json', publicBase).href;
$('certificate-url').value = new URL('rsa-a-certificate.pem', publicBase).href;

function decode() {
  try {
    const parsed = parseJwt($('jwt').value);
    $('decoded-header').textContent = JSON.stringify(parsed.header, null, 2);
    $('decoded-payload').textContent = JSON.stringify(parsed.payload, null, 2);
    $('jwt-status').textContent = `✓ 结构可解码 · ${parsed.header.alg} · 签名尚未验证`;
    $('jwt-status').className = 'field-hint valid';
  } catch (error) {
    $('decoded-header').textContent = '等待有效 JWT…'; $('decoded-payload').textContent = '等待有效 JWT…';
    $('jwt-status').textContent = $('jwt').value.trim() ? error.message : '支持三段式 JWS · 自动解析 Header 与 Payload';
    $('jwt-status').className = $('jwt').value.trim() ? 'field-hint invalid' : 'field-hint';
  }
}
function invalidate() {
  version++; rows = []; script = '';
  for (const id of ['download-txt', 'download-tsv', 'download-sh', 'copy-script', 'copy-command']) $(id).disabled = true;
  $('result-status').textContent = '等待生成'; $('result-status').className = 'status-badge';
  $('payload-count').textContent = '00'; $('category-count').textContent = '00';
  $('messages').replaceChildren();
  $('script-preview').textContent = '输入或配置已更新，请重新生成载荷。';
  $('selection-count').textContent = `${selected().length} 个类别已选择`;
  renderRows(); decode();
}
function renderRows() {
  const list = $('payload-list');
  const filter = $('filter').value.trim().toLowerCase();
  list.replaceChildren();
  if (!rows.length) {
    const empty = make('div', 'empty-state');
    empty.append(make('div', 'empty-icon', '{ · }'), make('h3', '', '你的测试，从一个 Token 开始'), make('p', '', '输入 JWT，选择测试类别，生成后在这里查看。'), make('span', '', 'INPUT → MUTATE → EXPORT'));
    list.append(empty); return;
  }
  const visible = rows.filter(row => `${row.id} ${row.category} ${row.label} ${row.token}`.toLowerCase().includes(filter));
  if (!visible.length) { list.append(make('div', 'empty-state', '没有匹配的载荷。')); return; }
  for (const row of visible) {
    const item = make('details', 'payload-row');
    const summary = document.createElement('summary');
    summary.append(make('span', 'row-id', row.id), make('span', 'row-label', row.label), make('span', 'row-tag', row.category));
    item.append(summary, make('div', 'payload-token', row.token));
    if (row.note) item.append(make('p', 'row-note', row.note));
    const button = make('button', 'text-button', '复制 JWT'); button.type = 'button';
    button.addEventListener('click', () => copy(row.token)); item.append(button); list.append(item);
  }
}
function message(text, error = false) { $('messages').append(make('div', error ? 'message error' : 'message', text)); }
for (const id of fields) $(id).addEventListener('input', invalidate);
$('filter').addEventListener('input', renderRows);
for (const [id, checked] of [['select-all', true], ['select-none', false]]) $(id).addEventListener('click', () => {
  document.querySelectorAll('#categories input').forEach(input => { input.checked = checked; }); invalidate();
});
$('example').addEventListener('click', async () => {
  const sampleVersion = version;
  const token = await signHmac({ alg: 'HS256', typ: 'JWT' }, { sub: '1234567890', name: 'JWT Lab', role: 'user', iat: 1700000000, exp: 4102444800 }, 'jwt-lab-example-secret');
  if (version !== sampleVersion) return;
  $('jwt').value = token;
  $('curl').value = "curl 'https://example.com/api/me' \\\n  -H 'Authorization: Bearer $JWT_HERE' \\\n  -H 'Accept: application/json'";
  $('custom-payload').value = JSON.stringify({ sub: 'admin', role: 'admin', exp: 4102444800 }, null, 2);
  invalidate(); toast('示例已载入；请换成你的授权测试请求');
});
$('generate').addEventListener('click', async () => {
  if (busy) return;
  invalidate();
  if (!selected().length) { message('请至少选择一个测试类别。', true); return; }
  if (!crypto.subtle) { message('此浏览器环境不支持 Web Crypto，请使用 HTTPS 或 localhost。', true); return; }
  busy = true; const generation = version;
  $('generate').disabled = true; $('generate').textContent = '正在生成…';
  try {
    const result = await generatePayloads($('jwt').value, {
      categories: selected(), targetPublicKey: $('public-key').value, jwksUrl: $('jwks-url').value,
      certificateUrl: $('certificate-url').value, secrets: $('secrets').value, customPayload: $('custom-payload').value,
    });
    if (generation !== version) return;
    rows = result.rows;
    result.warnings.forEach(warning => message(warning));
    if (rows.length) {
      $('download-txt').disabled = false; $('download-tsv').disabled = false;
      try {
        script = generateRunner($('curl').value, rows);
        $('download-sh').disabled = false; $('copy-script').disabled = false; $('copy-command').disabled = false;
        $('script-preview').textContent = script;
      } catch (error) {
        message(`载荷已生成；脚本尚未生成：${error.message}`);
        $('script-preview').textContent = error.message;
      }
    }
    $('payload-count').textContent = String(rows.length).padStart(2, '0');
    $('category-count').textContent = String(new Set(rows.map(row => row.category)).size).padStart(2, '0');
    $('result-status').textContent = rows.length ? '生成完成' : '无可生成载荷';
    $('result-status').className = 'status-badge ready'; renderRows();
    if (rows.length) toast(`已生成 ${rows.length} 条测试载荷`);
  } catch (error) {
    if (generation === version) message(error.message, true);
  } finally {
    busy = false; $('generate').disabled = false;
    $('generate').replaceChildren(document.createTextNode('生成测试载荷 '), make('span', '', '→'));
  }
});
$('download-txt').addEventListener('click', () => download('payloads.txt', rows.map(row => row.token).join('\n') + '\n'));
$('download-tsv').addEventListener('click', () => download('payload-manifest.tsv', manifestTsv(rows), 'text/tab-separated-values;charset=utf-8'));
$('download-sh').addEventListener('click', () => download('jwt-runner.sh', script, 'text/x-shellscript;charset=utf-8'));
$('copy-command').addEventListener('click', () => copy('bash jwt-runner.sh payloads.txt'));
$('copy-script').addEventListener('click', () => copy(script));
decode();
