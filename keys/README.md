# Public test keys — deliberately public

所有密钥刻意公开，只供实验。Never use these private keys for production authentication.

| ID / kid | Algorithm | Files |
| --- | --- | --- |
| jwt-lab-rsa-a | RSA-2048 / RS256 | rsa-a-private.pem, rsa-a-public.pem, rsa-a-certificate.pem |
| jwt-lab-rsa-b | RSA-2048 / RS256 | rsa-b-private.pem, rsa-b-public.pem |
| jwt-lab-ec | P-256 / ES256 | ec-private.pem, ec-public.pem |

`jwks.json` 包含三把公钥，不含私有参数。`rsa-a-certificate.pem` 是与 RSA-A 匹配的自签名 X.509 证书，供 x5u 测试，不是 HTTPS 服务器证书。

私钥为 PKCS#8 PEM，公钥为 SPKI PEM。浏览器直接从 `src/keys.js` 打包导入相同材料，不在生成期间下载密钥。

JKU 默认指向部署站点的 `keys/jwks.json`；x5u 默认指向 `keys/rsa-a-certificate.pem`。结果取决于目标是否错误地信任这些来源，不保证接受任何载荷。

PEM、模块、JWKS、证书必须同时更新，运行 `node --test` 校验一致性。
