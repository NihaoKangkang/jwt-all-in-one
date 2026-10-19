# JWT All in One

[中文文档](./README.zh-CN.md) · [English interface](https://www.kyiwong.com/jwt-all-in-one/?lang=en)

A browser-only JWT security workbench. Decode a JWS, choose payload categories, and **copy one complete Bash command** that embeds every payload and replays your curl request. No generated script or input file needs to be downloaded.

Site: <https://www.kyiwong.com/jwt-all-in-one/>. The project inherits the account's existing GitHub Pages custom domain. HTTP visits are upgraded to HTTPS for Web Crypto. A queued Pages deployment is not a live site; check [Actions](https://github.com/NihaoKangkang/jwt-all-in-one/actions).

## Use

1. Enter a three-part JWS. Decode results do not establish signature validity. Five-part JWE is outside the current format support.
2. Paste **Copy as cURL (bash)** from your browser and replace the JWT with literal `$JWT_HERE`:

   ```bash
   curl 'https://your-authorized-host.example/api/me' \
     -H 'Authorization: Bearer $JWT_HERE' \
     -H 'Accept: application/json'
   ```

   Placeholders work in headers, cookies, URLs, and bodies, including single-quoted arguments and repeated occurrences. The parser handles a single Bash/POSIX curl command, not pipes, redirects, other shell variables, command substitutions, or multiple commands. Output, configuration, and parallel flags are rejected because the generated command captures responses itself. Windows CMD / PowerShell curl must first be converted to Bash syntax.
3. Categories are selected by default. Uncheck unwanted tests. Configure the actual target RSA public key for RS/HS confusion; repository fixture keys are not a substitute. Advanced options support custom Header/Payload JSON, your own signing key, field fuzzing, delay, timeout, and a response canary.
4. Click **Generate payloads**, then **Copy complete test command**. Paste the entire block into a terminal with Bash and curl. The block contains a quoted heredoc, labels, every JWT, and a `for` loop. It executes independently of the repository; it does not fetch remote executable code. TXT/TSV downloads and **Copy all JWTs** remain optional.
5. Inspect each JWT, HTTP status, curl exit code, headers, and response body. The command writes `jwt-results.XXXXXX/summary.tsv` and numbered `.jwt.txt`, `.headers`, `.body`, and `.stderr` files. Each summary row also includes literal canary matching and exact comparison against the original baseline body. Neither comparison establishes a vulnerability on its own. Failures do not stop later requests.

Default delay: 0.2 seconds; adjustable from 0 to 60. Default timeout: 30 seconds; adjustable from 1 to 300. Connect timeout: 10 seconds. Compatible with macOS Bash 3 and Linux Bash.

## Payloads and local tools

| Feature | Implementation |
| --- | --- |
| Original baseline | Preserve the original token byte for byte |
| alg=none | Four case variants, empty signature and missing final dot; disabling also excludes custom/duplicate-alg none combinations |
| Signature mutations | Empty, missing, truncated, modified, random signatures and extra segments |
| HMAC candidates | Empty HS256/384/512 keys, common weak keys, up to 100 generated candidate payloads |
| RS/HS confusion | Actual target RSA public key as LF/CRLF/no-final-newline PEM or DER HMAC material |
| Embedded JWK | Two RSA and one P-256 fixture, correctly signed with matching private keys |
| JKU / x5u | Public JWKS / matching X.509 certificate URLs and corresponding signatures |
| kid | Empty values, missing keys, traversal, empty-file paths, SQL strings, original/empty-HMAC signatures |
| Claims / parser | Claims and timestamps, typ/crit/b64, duplicate alg, Base64 and padding differences |
| ECDSA zero values | ES256/384/512 all-zero JOSE signatures and intentional DER variations |
| Custom signing | Header/Payload JSON with supplied secret, PKCS#8 PEM or private JWK |
| Field fuzzing | Header or payload dot paths; up to 50 JSON values or literal strings; selected signature combinations |
| Signature verification | HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA (Ed25519); secret/SPKI/JWK/JWKS |
| Offline dictionary | Actual HMAC signature checking in a cancellable Worker; up to 10,000 supplied candidates plus the empty secret |
| Key generation | RSA-2048, P-256/P-384/P-521 and Ed25519; export PKCS#8 private PEM, SPKI public PEM and public JWKS |
| Key reconstruction | Convert supplied public JWK/JWKS to SPKI public PEM |
| Languages | EN / ZH switch; English direct link uses `?lang=en` |

Some algorithms depend on browser Web Crypto support; unsupported operations return an error. Verification reports signature and numeric exp/nbf timing only, not issuer/audience trust or application authorization. Some mutation payloads intentionally retain an invalid original signature to test whether the target ignores verification.

## Privacy and public fixtures

Runtime code has no third-party dependencies, CDN, analytics, token storage, or backend. Tokens, keys, and requests stay in page memory. CSP `connect-src 'none'` blocks application fetch/XHR connections; static page/module/Worker loading still accesses the hosting site. Target requests only occur after you execute the copied terminal command. The command contains your request and credentials: keep it and its results local.

[`keys/`](./keys/) intentionally publishes two RSA-2048 pairs, a P-256 pair, JWKS, and the matching RSA-A self-signed certificate. **Every fixture private key is public. Never use these fixtures for real authentication.** The same fixtures are bundled in `src/keys.js`, so payload generation does not fetch keys. Custom JKU/x5u URLs must host matching public material. Locally generated keys are not published.

## Development and checks

No install or build step:

```bash
git clone https://github.com/NihaoKangkang/jwt-all-in-one.git
cd jwt-all-in-one
python3 -m http.server 4173 --bind 127.0.0.1
# Open http://127.0.0.1:4173/?lang=en
```

Use a modern browser on HTTPS or localhost, not a file:// URL. Tests require Node.js 22+ and curl:

```bash
npm test
# or node --test
```

Tests independently verify all 13 signing algorithms with Node crypto, fixtures and JWKS consistency, dictionary results, category filtering, fuzzing, and the copied command's real execution against a local HTTP server with headers, cookies, URLs, bodies, failures, and saved results.

[Pages workflow](./.github/workflows/pages.yml): PRs test; pushes to `main` test and deploy the static site. Pages Source must be **GitHub Actions**. Published files are only the HTML, favicon, `src/`, and `keys/`. Relative asset paths support project subdirectories.

Independently implemented with inspiration from [jwt_tool](https://github.com/ticarpi/jwt_tool); no GPL implementation copied. This is not a claim of complete CLI compatibility. MIT License. Use only in environments you are authorized to test.
