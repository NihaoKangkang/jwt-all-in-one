import { parseJwt, signHmac } from './jwt.js';
import { CATEGORIES, generatePayloads } from './payloads.js';
import { generateCommand, manifestTsv } from './curl.js';
import { generateKeyPair, publicKeyFromJwks, verifyToken } from './crypto-tools.js';
import { language, observeTranslations, switchLanguage, translate } from './i18n.js';

// GitHub account-level custom domains may redirect project URLs to HTTP.
// Web Crypto needs a secure context; upgrade before the user enters credentials.
if (location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)) {
  const secureUrl = new URL(location.href);
  secureUrl.protocol = 'https:';
  location.replace(secureUrl.href);
}

const $ = id => document.getElementById(id);
let rows = [], script = '', version = 0, busy = false, toastTimer, auditWorker, generatedKeys;
const fields = ['jwt', 'curl', 'public-key', 'jwks-url', 'certificate-url', 'secrets', 'custom-payload', 'custom-header', 'signing-key', 'delay', 'timeout', 'canary', 'fuzz-field', 'fuzz-values'];
const translatedRows = () => rows.map(row => ({ ...row, label: translate(row.label, language), note: translate(row.note, language) }));
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
    $('decoded-header').textContent = translate('等待有效 JWT…', language); $('decoded-payload').textContent = translate('等待有效 JWT…', language);
    $('jwt-status').textContent = $('jwt').value.trim() ? error.message : '支持三段式 JWS · 自动解析 Header 与 Payload';
    $('jwt-status').className = $('jwt').value.trim() ? 'field-hint invalid' : 'field-hint';
  }
}
function invalidate() {
  version++; rows = []; script = '';
  for (const id of ['download-txt', 'download-tsv', 'copy-payloads', 'copy-script', 'copy-command']) $(id).disabled = true;
  $('result-status').textContent = '等待生成'; $('result-status').className = 'status-badge';
  $('payload-count').textContent = '00'; $('category-count').textContent = '00';
  $('messages').replaceChildren();
  $('script-preview').textContent = translate('输入或配置已更新，请重新生成载荷。', language);
  $('command-hint').textContent = translate('生成后，点击上方按钮复制完整命令', language);
  $('selection-count').textContent = `${selected().length} 个类别已选择`;
  renderRows(); decode();
}
function renderRows() {
  const list = $('payload-list');
  const filter = $('filter').value.trim().toLowerCase();
  list.replaceChildren();
  if (!rows.length) {
    const empty = make('div', 'empty-state');
    empty.append(make('div', 'empty-icon', '{·}'), make('h3', '', '你的测试，从一个 Token 开始'), make('p', '', '输入 JWT，选择测试类别，生成后在这里查看。'), make('span', '', 'INPUT → MUTATE → EXPORT'));
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
$('sign-with-key').addEventListener('change', invalidate);
$('signing-format').addEventListener('change', invalidate);
$('fuzz-part').addEventListener('change', invalidate);
$('jwt').addEventListener('input', () => { stopDictionary(); $('verification-result').textContent = ''; $('dictionary-result').textContent = ''; });
$('verification-key').addEventListener('input', () => { $('verification-result').textContent = ''; });
$('verification-format').addEventListener('change', () => { $('verification-result').textContent = ''; });
$('dictionary').addEventListener('input', () => { stopDictionary(); $('dictionary-result').textContent = ''; });
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
      customHeader: $('custom-header').value, signingKey: $('signing-key').value, signWithKey: $('sign-with-key').checked,
      signingFormat: $('signing-format').value,
      fuzzPart: $('fuzz-part').value, fuzzField: $('fuzz-field').value, fuzzValues: $('fuzz-values').value,
    });
    if (generation !== version) return;
    rows = result.rows;
    result.warnings.forEach(warning => message(warning));
    if (rows.length) {
      $('download-txt').disabled = false; $('download-tsv').disabled = false; $('copy-payloads').disabled = false;
      try {
        buildCommand();
      } catch (error) {
        message(`载荷已生成；命令尚未生成：${error.message}`);
        $('script-preview').textContent = translate(error.message, language);
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
$('download-tsv').addEventListener('click', () => download('payload-manifest.tsv', manifestTsv(translatedRows()), 'text/tab-separated-values;charset=utf-8'));
$('copy-command').addEventListener('click', () => copy(script));
$('copy-payloads').addEventListener('click', () => copy(rows.map(row => row.token).join('\n')));
$('copy-script').addEventListener('click', () => copy(script));
function buildCommand() {
  script = generateCommand($('curl').value, translatedRows(), { delay: $('delay').value, timeout: $('timeout').value, canary: $('canary').value });
  $('copy-script').disabled = false; $('copy-command').disabled = false;
  $('script-preview').textContent = script;
  $('command-hint').textContent = `${rows.length} JWTs → for loop → curl → summary.tsv`;
}
$('language').addEventListener('click', () => {
  switchLanguage(); decode();
  if (script) buildCommand();
  else {
    $('script-preview').textContent = translate('生成载荷并填写 curl 后，在这里预览命令。', language);
    $('command-hint').textContent = translate('生成后，点击上方按钮复制完整命令', language);
  }
});
$('verify').addEventListener('click', async () => {
  const token = $('jwt').value, material = $('verification-key').value, format = $('verification-format').value;
  try {
    const result = await verifyToken(token, material, { format });
    if ($('jwt').value !== token || $('verification-key').value !== material || $('verification-format').value !== format) return;
    $('verification-result').textContent = `${result.valid ? '签名有效' : '签名无效'} · ${result.invalidTimeClaims ? '时间声明无效' : result.expired ? '已过期' : result.notYetValid ? '尚未生效' : '时间范围有效'}`;
  } catch (error) {
    if ($('jwt').value === token && $('verification-key').value === material && $('verification-format').value === format) $('verification-result').textContent = error.message;
  }
});
$('reconstruct').addEventListener('click', async () => {
  try {
    const header = parseJwt($('jwt').value).header;
    download('reconstructed-public.pem', await publicKeyFromJwks($('verification-key').value, header));
  } catch (error) { $('verification-result').textContent = error.message; }
});
function stopDictionary() {
  auditWorker?.terminate(); auditWorker = null;
  $('check-dictionary').disabled = false; $('cancel-dictionary').disabled = true;
}
$('cancel-dictionary').addEventListener('click', () => { stopDictionary(); $('dictionary-result').textContent = '检查已取消'; });
$('check-dictionary').addEventListener('click', () => {
  stopDictionary();
  $('dictionary-result').textContent = '正在检查…';
  try {
    parseJwt($('jwt').value);
    const words = $('dictionary').value.split(/\r?\n/).filter(value => value.length);
    if (words.length > 10000) throw new Error('Dictionary is limited to 10,000 supplied candidates.');
    const worker = new Worker(new URL('./audit-worker.js', import.meta.url), { type: 'module' });
    auditWorker = worker;
    $('check-dictionary').disabled = true; $('cancel-dictionary').disabled = false;
    worker.onmessage = ({ data }) => {
      if (worker !== auditWorker) return;
      if (data.progress) $('dictionary-result').textContent = `已检查 ${data.progress.checked} / ${data.progress.total}`;
      if (data.result) {
        const { found, secret, checked } = data.result;
        $('dictionary-result').replaceChildren(make('span', '', found ? '找到密钥：' : '未找到匹配密钥'), make('code', '', found ? JSON.stringify(secret) : ` (${checked})`));
      }
      if (data.error) $('dictionary-result').textContent = data.error;
      if (data.result || data.error) stopDictionary();
    };
    worker.onerror = () => {
      if (worker !== auditWorker) return;
      $('dictionary-result').textContent = 'Worker unavailable. Use a modern browser over HTTPS or localhost.'; stopDictionary();
    };
    worker.postMessage({ token: $('jwt').value, words });
  } catch (error) { $('dictionary-result').textContent = error.message; stopDictionary(); }
});
$('keygen').addEventListener('click', async () => {
  $('keygen').disabled = true; $('keygen-result').textContent = '正在生成密钥…';
  try {
    generatedKeys = await generateKeyPair($('key-algorithm').value);
    for (const id of ['save-public', 'save-private', 'save-jwks']) $(id).disabled = false;
    $('keygen-result').textContent = '密钥对已生成，仅保存在页面内存。';
  } catch (error) { $('keygen-result').textContent = error.message; }
  finally { $('keygen').disabled = false; }
});
$('save-public').addEventListener('click', () => download('generated-public.pem', generatedKeys.publicPem));
$('save-private').addEventListener('click', () => download('generated-private.pem', generatedKeys.privatePem));
$('save-jwks').addEventListener('click', () => download('generated-jwks.json', JSON.stringify(generatedKeys.jwks, null, 2), 'application/json'));
decode();
$('script-preview').textContent = translate('生成载荷并填写 curl 后，在这里预览命令。', language);
$('command-hint').textContent = translate('生成后，点击上方按钮复制完整命令', language);
$('selection-count').textContent = `${selected().length} 个类别已选择`;
observeTranslations();
