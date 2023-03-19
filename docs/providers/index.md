# Providers

On current moment following providers are available out of the box:

* [JDK](jdk.md) - based on
  JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
  (javax.crypto.* / java.security.*)
* [WebCrypto](webcrypto.md) - based on
  [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
* [Apple](apple.md) - based on
  [CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html)
* [OpenSSL3](openssl3.md) - based on [OpenSSL 3.x](https://www.openssl.org),
  statically linked to prebuilt OpenSSL 3.0.8 or dynamically linked (experimental)

## Supported primitives

While library is overall multiplatform and all algorithms/operations interfaces are available on all targets,
support for specific algorithm for specific target depends on used provider.
Below there are several tables which shows what is supported and what not
(I know, that it's not the easiest thing to understand... But we have what we have).
For additional limitation please consult provider specific documentation

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
