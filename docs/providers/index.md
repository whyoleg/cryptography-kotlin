# Providers

On current moment following providers are available out of the box:

* [JDK](../modules/cryptography-provider-jdk.md) - via
  JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
* [WebCrypto](../modules/cryptography-provider-webcrypto.md) - via
  [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
* [Apple](../modules/cryptography-provider-apple.md) - via
  [CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html)
* [OpenSSL3](../modules/cryptography-provider-openssl3.md) - via [OpenSSL 3.x](https://www.openssl.org),
  statically linked to prebuilt OpenSSL 3.0.8 or dynamically linked (experimental)

## Supported primitives

While the library is overall multiplatform and all algorithm/operation interfaces are available on all targets,
support for a specific algorithm for a specific target depends on the used provider.
Below there are several tables which show what is supported and what not
(I know that it's not the easiest thing to understand...
But we have what we have).

For additional limitation please consult provider specific documentation.

### Supported targets per provider

| Target                                    | jdk | webcrypto | apple | openssl3        |
|-------------------------------------------|-----|-----------|-------|-----------------|
| jvm                                       | ✅   | ➖         | ➖     | ❌               |
| js                                        | ➖   | ✅         | ➖     | ❌               |
| iosX64<br/>iosSimulatorArm64<br/>iosArm64 | ➖   | ➖         | ✅     | ✅ prebuilt only |
| macosX64<br/>macosArm64                   | ➖   | ➖         | ✅     | ✅               |
| linuxX64                                  | ➖   | ➖         | ➖     | ✅               |
| mingwX64                                  | ➖   | ➖         | ➖     | ✅               |

> ✅ : supported
>
> ➖ : not applicable
>
> ❌ : not supported (yet?)

### Supported algorithms per provider

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

> ⚠️ : insecure algorithm
>
> ✅ : supported
>
> ❌ : not supported (yet?)
