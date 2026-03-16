# Supported Algorithms

> `supported` here means that those algorithms are tested and works at least in some configuration
> (f.e. different Java versions or Java providers can have different algorithms supported)

| Operation                                   | Algorithm         | jdk | webcrypto | apple | cryptokit | openssl3 |
|---------------------------------------------|-------------------|:---:|:---------:|:-----:|-----------|:--------:|
| **Digest**                                  | SHA224            |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | SHA256            |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA384            |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA512            |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA3 family       |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
|                                             | ⚠️ SHA1           |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | ⚠️ MD5            |  ✅  |     ❌     |   ✅   | ✅         |    ✅     |
|                                             | ⚠️ RIPEMD160      |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
| **MAC**                                     | HMAC              |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | CMAC              |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
| **Symmetric-key<br/>encryption/decryption** | AES-CBC           |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | AES-CTR           |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | AES-GCM           |  ✅  |     ✅     |   ❌   | ✅         |    ✅     |
|                                             | AES-CCM           |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
|                                             | ChaCha20-Poly1305 |  ✅  |     ❌     |   ❌   | ✅         |    ✅     |
|                                             | ⚠️ AES-ECB        |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ AES-OFB        |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ AES-CFB        |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ AES-CFB8       |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
| **Public-key<br/>encryption/decryption**    | RSA-OAEP          |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ RSA-PKS1-v1_5  |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ RSA-RAW        |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
| **Digital Signatures**                      | ECDSA (Message)   |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | ECDSA (Digest)    |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | EdDSA             |  ✅  |     ✅     |   ❌   | ✅         |    ✅     |
|                                             | DSA               |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
|                                             | RSA-SSA-PSS       |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | RSA-PKS1-v1_5     |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
| **Key Agreement**                           | ECDH              |  ✅  |     ✅     |   ❌   | ✅         |    ✅     |
|                                             | XDH               |  ✅  |     ✅     |   ❌   | ✅         |    ✅     |
|                                             | DH                |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
| **PRF/KDF**                                 | PBKDF2            |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | HKDF              |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |

> ⚠️ : use carefully
>
> ✅ : supported
>
> ❌ : not supported (yet?)
