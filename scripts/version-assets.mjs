import { readFile, writeFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const { version } = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const check = process.argv.includes('--check');
const files = ['index.html', ...((await readdir(join(root, 'src'))).filter(name => /\.(js|css)$/.test(name)).map(name => `src/${name}`))];
const stale = [];
for (const file of files) {
  const path = join(root, file);
  const original = await readFile(path, 'utf8');
  let content = original;
  if (file.endsWith('.js')) {
    content = content.replace(/((?:from\s*|import\s*)['"])(\.\/[^'"]+\.js)(?:\?v=[^'"]+)?(['"])/g, `$1$2?v=${version}$3`);
    content = content.replace(/(['"])(\.\/audit-worker\.js)(?:\?v=[^'"]+)?\1/g, `$1$2?v=${version}$1`);
  }
  if (file.endsWith('.css')) content = content.replace(/(url\(['"])(\.\/[^'"]+\.css)(?:\?v=[^'"]+)?(['"]\))/g, `$1$2?v=${version}$3`);
  if (file === 'index.html') {
    content = content.replace(/((?:src|href)=['"])(\.\/(?:src\/[^'"]+\.(?:js|css)|favicon\.svg|keys\/README\.md))(?:\?v=[^'"]+)?(['"])/g, `$1$2?v=${version}$3`);
    content = content.replace(/v\d+\.\d+\.\d+ \/ OPEN SOURCE/g, `v${version} / OPEN SOURCE`);
  }
  if (content !== original) {
    stale.push(file);
    if (!check) await writeFile(path, content);
  }
}
if (check && stale.length) {
  process.stderr.write(`Asset versions do not match ${version}: ${stale.join(', ')}. Run npm run version-assets.\n`);
  process.exitCode = 1;
} else process.stdout.write(`Asset versions match ${version}.\n`);
