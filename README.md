# cryptography-kotlin

Types-safe Multiplatform cryptography library for Kotlin.

## Supported targets per provider

> Provider artifacts are `cryptography-NAME` (e.g. `cryptography-openssl3`)

| target                                    | jdk | webcrypto | apple | openssl3         |
|-------------------------------------------|-----|-----------|-------|------------------|
| jvm                                       | ✅   | ➖         | ➖     | ❌                |
| js                                        | ➖   | ✅         | ➖     | ❌                |
| wasm                                      | ➖   | soon      | ➖     | ❌                |
| iosX64<br/>iosSimulatorArm64<br/>iosArm64 | ➖   | ➖         | ✅     | ✅ only static    |
| tvOS<br/>watchOS                          | ➖   | ➖         | ✅     | soon only static |
| macosX64<br/>macosArm64                   | ➖   | ➖         | ✅     | ✅                |
| linuxX64                                  | ➖   | ➖         | ➖     | ✅                |
| mingwX64                                  | ➖   | ➖         | ➖     | ✅                |

## Supported algorithms per provider

> Provider artifacts are `cryptography-NAME` (e.g. `cryptography-openssl3`)

| Operation                                   | Algorithm   | jdk | webcrypto | apple | openssl3 |
|---------------------------------------------|-------------|:---:|:---------:|:-----:|:--------:|
| **Digest**                                  | ⚠️ MD5      |  ✅  |     ❌     |   ✅   |    ✅     |
|                                             | ⚠️ SHA1     |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | SHA256      |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | SHA384      |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | SHA512      |  ✅  |     ✅     |   ✅   |    ✅     |
| **MAC**                                     | HMAC        |  ✅  |     ✅     |   ✅   |    ✅     |
| **Symmetric-key<br/>encryption/decryption** | AES-CBC     |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | AES-GCM     |  ✅  |     ✅     |   ❌   |    ✅     |
| **Public-key<br/>encryption/decryption**    | RSA-OAEP    |  ✅  |     ✅     |   ❌   |    ✅     |
| **Digital Signatures**                      | ECDSA       |  ✅  |     ✅     |   ❌   |    ✅     |
|                                             | RSA-SSA-PSS |  ✅  |     ✅     |   ❌   |    ✅     |
