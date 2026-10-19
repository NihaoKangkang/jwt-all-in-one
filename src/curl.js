export const shellQuote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";

// Parse a single shell command into argv. Never evaluate user-provided shell source.
export function parseCurl(source) {
  if (!source.trim()) throw new Error('请输入完整 curl 命令，并用 $JWT_HERE 标记 JWT。');
  const args = [];
  let value = '', quote = null, started = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === '\\' && quote !== "'") {
      const next = source[++i];
      if (next === undefined) throw new Error('curl 命令末尾存在未完成的转义。');
      if (next === '\n') continue;
      if (quote === '"' && !['$', '`', '"', '\\'].includes(next)) value += '\\';
      value += next; started = true; continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      else value += char;
      continue;
    }
    if (char === '"' || char === "'") { quote = char; started = true; continue; }
    if ((char === '\n' || char === '\r') && (args.length || started) && source.slice(i + 1).trim()) {
      throw new Error('多行 curl 请使用反斜杠续行；不支持多条命令。');
    }
    if (/\s/.test(char)) {
      if (started) { args.push(value); value = ''; started = false; }
      continue;
    }
    if (';|&<>`'.includes(char) || (char === '$' && ['(', '{'].includes(source[i + 1]))) throw new Error('仅支持单条 curl 命令；请移除管道、重定向、命令替换及 shell 表达式。');
    value += char; started = true;
  }
  if (quote) throw new Error('curl 命令引号未闭合。');
  if (started) args.push(value);
  if (args.shift() !== 'curl') throw new Error('命令必须以 curl 开始。');
  if (!args.some(arg => arg.includes('$JWT_HERE'))) throw new Error('curl 命令缺少 $JWT_HERE 占位符。');
  const controlled = /^(--(?:next|config|output|output-dir|remote-name|remote-name-all|remote-header-name|dump-header|write-out|stderr|trace|trace-ascii|libcurl|parallel|url-query))(?:=|$)/;
  for (const arg of args) {
    if (controlled.test(arg) || /^-[^-]*[KoODwZ]/.test(arg)) throw new Error('请移除 curl 的输出、配置文件、并发或 --next 选项；结果保存由批量脚本统一处理。');
    if (/\$[A-Za-z_{(]|`/.test(arg.replaceAll('$JWT_HERE', ''))) throw new Error('除 $JWT_HERE 外不支持其他 shell 变量或命令替换，请填入实际值。');
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(arg)) throw new Error('curl 命令含有不支持的控制字符。');
  }
  return args;
}

export function generateCommand(template, rows, options = {}) {
  const args = parseCurl(template);
  const command = args.map(arg => arg.split('$JWT_HERE').map(shellQuote).join('"$JWT_HERE"')).join(' ');
  const labels = rows.map(row => shellQuote(`${row.id} | ${row.category} | ${row.label}`.replace(/[\t\r\n]/g, ' '))).join('\n  ');
  const payloads = rows.map(row => shellQuote(row.token)).join('\n  ');
  const delay = Number(options.delay ?? 0.2), timeout = Number(options.timeout ?? 30);
  if (!Number.isFinite(delay) || delay < 0 || delay > 60 || !Number.isFinite(timeout) || timeout < 1 || timeout > 300) throw new Error('请求间隔须为 0–60 秒，超时须为 1–300 秒。');
  const canary = shellQuote(options.canary ?? '');
  const baseline = rows.findIndex(row => row.category === 'baseline') + 1;
  const body = `#!/usr/bin/env bash
# Generated locally by JWT All in One. Requires Bash and curl; macOS Bash 3 supported.
# Paste this entire block into a terminal. No downloaded script or payload file required.
set -u
command -v curl >/dev/null 2>&1 || { printf 'curl is required\\n' >&2; exit 1; }
results_dir=$(mktemp -d ./jwt-results.XXXXXX) || exit 1
canary=${canary}
baseline_prefix=''
printf 'index\\tlabel\\thttp_status\\tcurl_exit\\tresponse_bytes\\tseconds\\tcanary_match\\tsame_body_as_baseline\\n' > "$results_dir/summary.tsv"
labels=(
  ${labels}
)
payloads=(
  ${payloads}
)
index=0
for JWT_HERE in "\${payloads[@]}"; do
  index=$((index + 1))
  case "$JWT_HERE" in *[!A-Za-z0-9_.=+/-]*) printf 'Invalid payload at line %s\\n' "$index" >&2; continue ;; esac
  printf -v prefix '%s/%04d' "$results_dir" "$index"
  label="\${labels[$((index - 1))]:-custom-payload}"
  printf '%s\\n' "$JWT_HERE" > "$prefix.jwt.txt"
  printf '\\n===== %04d | %s =====\\nJWT: %s\\n' "$index" "$label" "$JWT_HERE"
  metrics=$(curl -q ${command} --silent --show-error --connect-timeout 10 --max-time ${timeout} --output "$prefix.body" --dump-header "$prefix.headers" --write-out '%{http_code}\\t%{size_download}\\t%{time_total}' 2> "$prefix.stderr")
  curl_exit=$?
  IFS=$'\\t' read -r status size seconds <<< "$metrics"
  canary_match='n/a'; same_body='n/a'
  if [[ -n "$canary" ]]; then
    canary_match='no'
    if [[ -f "$prefix.body" ]] && grep -F -q -- "$canary" "$prefix.body"; then canary_match='yes'; fi
  fi
  if [[ "$index" -eq ${baseline} && "$curl_exit" -eq 0 && -f "$prefix.body" ]]; then baseline_prefix="$prefix"; fi
  if [[ -n "$baseline_prefix" && -f "$prefix.body" ]]; then
    same_body='no'
    if cmp -s "$baseline_prefix.body" "$prefix.body"; then same_body='yes'; fi
  fi
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$index" "$label" "\${status:-000}" "$curl_exit" "\${size:-0}" "\${seconds:-0}" "$canary_match" "$same_body" >> "$results_dir/summary.tsv"
  printf 'HTTP: %s | curl exit: %s | bytes: %s | seconds: %s\\n' "\${status:-000}" "$curl_exit" "\${size:-0}" "\${seconds:-0}"
  [[ ! -s "$prefix.stderr" ]] || cat "$prefix.stderr"
  printf '%s\\n' '--- response headers ---'
  [[ ! -f "$prefix.headers" ]] || cat "$prefix.headers"
  printf '\\n%s\\n' '--- response body ---'
  [[ ! -f "$prefix.body" ]] || cat "$prefix.body"
  printf '\\n'
  sleep ${delay}
done
printf '\\nResults: %s\\nSummary: %s/summary.tsv\\n' "$results_dir" "$results_dir"
`;
  let delimiter = 'JWT_ALL_IN_ONE_COMMAND';
  while (body.split('\n').includes(delimiter)) delimiter += '_END';
  return `bash <<'${delimiter}'\n${body}${delimiter}\n`;
}

export function manifestTsv(rows) {
  const clean = value => String(value).replace(/[\t\r\n]/g, ' ');
  return ['id\tcategory\tlabel\tnote\tjwt', ...rows.map(row => [row.id, row.category, row.label, row.note, row.token].map(clean).join('\t'))].join('\n') + '\n';
}
