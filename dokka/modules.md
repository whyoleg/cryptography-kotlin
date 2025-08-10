# Module cryptography-bigint

[BigInt][BigInt]: an arbitrary-precision integer.

[BigInt]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-bigint/dev.whyoleg.cryptography.bigint/-big-int/index.html

# Package dev.whyoleg.cryptography.bigint

[BigInt][BigInt]: an arbitrary-precision integer.

[BigInt]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-bigint/dev.whyoleg.cryptography.bigint/-big-int/index.html

# Module cryptography-random

[CryptographyRandom][CryptographyRandom]: zero-dependency platform-dependent CSPRNG exposed via [kotlin.Random][kotlin.Random] API

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[CryptographyRandom]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-random/dev.whyoleg.cryptography.random/-cryptography-random/index.html

# Package dev.whyoleg.cryptography.random

[CryptographyRandom][CryptographyRandom]: zero-dependency platform-dependent CSPRNG exposed via [kotlin.Random][kotlin.Random] API

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[CryptographyRandom]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-random/dev.whyoleg.cryptography.random/-cryptography-random/index.html

# Module cryptography-core

Provides multiplatform API to build, get and use cryptography primitives

# Package dev.whyoleg.cryptography

Provides core primitives for creating and accessing [CryptographyAlgorithm][CryptographyAlgorithm]
and [CryptographyProvider][CryptographyProvider]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptographyAlgorithm]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-algorithm/index.html

# Package dev.whyoleg.cryptography.algorithms

Provides common algorithms:

* digests (e.g [SHA256][SHA256] and [SHA512][SHA512])
* symmetric ciphers ([AES][AES])
* asymmetric encryption and signature ([RSA][RSA] and [ECDSA][ECDSA])
* MAC ([HMAC][HMAC])
* Key derivation ([PBKDF2][PBKDF2] and [HKDF][HKDF])
* Key agreement ([ECDH][ECDH])

[SHA256]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-s-h-a256/index.html

[SHA512]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-s-h-a512/index.html

[AES]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-a-e-s/index.html

[HMAC]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-h-m-a-c/index.html

[RSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-r-s-a/index.html

[ECDSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-e-c-d-s-a/index.html

[ECDH]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-e-c-d-h/index.html

[PBKDF2]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-p-b-k-d-f2/index.html

[HKDF]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-h-k-d-f/index.html

# Package dev.whyoleg.cryptography.operations

Provides APIs to perform cryptography operations:

* [hashing][Hasher]
* [encryption][Encryptor]/[decryption][Decryptor] and
  Authenticated [encryption][AuthenticatedEncryptor]/[decryption][AuthenticatedDecryptor]
* signature [verification][SignatureVerifier] and [generation][SignatureGenerator]
* [secret derivation][SecretDerivation] (KDF/PRF) and [shared secret derivation][SharedSecretDerivation] (Key agreement)

[Encryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-encryptor/index.html

[Decryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-decryptor/index.html

[AuthenticatedEncryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/index.html

[AuthenticatedDecryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/index.html

[Hasher]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-hasher/index.html

[SignatureVerifier]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/index.html

[SignatureGenerator]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/index.html

[SecretDerivation]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-secret-derivation/index.html

[SharedSecretDerivation]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-shared-secret-derivation/index.html

# Package dev.whyoleg.cryptography.materials.key

Provides API for working with keys: [encoding][EncodableKey], [decoding][KeyDecoder] and [generation][KeyGenerator]

[EncodableKey]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-encodable-key/index.html

[KeyDecoder]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-key-decoder/index.html

[KeyGenerator]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-key-generator/index.html

# Module cryptography-serialization-asn1

ASN.1/[DER][DER]: binary serialization of ASN.1/DER content via [kotlinx.serialization][kotlinx.serialization]

[DER]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1/dev.whyoleg.cryptography.serialization.asn1/-d-e-r/index.html

[kotlinx.serialization]: https://github.com/Kotlin/kotlinx.serialization

# Package dev.whyoleg.cryptography.serialization.asn1

ASN.1/[DER][DER]: binary serialization of ASN.1/DER content via [kotlinx.serialization][kotlinx.serialization]

[DER]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1/dev.whyoleg.cryptography.serialization.asn1/-d-e-r/index.html

[kotlinx.serialization]: https://github.com/Kotlin/kotlinx.serialization

# Module cryptography-serialization-asn1-modules

ASN.1 modules/declarations from different RFCs, f.e.
[SubjectPublicKeyInfo][SubjectPublicKeyInfo] from [RFC5280][RFC5280] and [PrivateKeyInfo][PrivateKeyInfo] from [RFC5208][RFC5208]

[SubjectPublicKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-subject-public-key-info/index.html

[PrivateKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-private-key-info/index.html

[RFC5280]: https://datatracker.ietf.org/doc/html/rfc5280

[RFC5208]: https://datatracker.ietf.org/doc/html/rfc5208

# Package dev.whyoleg.cryptography.serialization.asn1.modules

ASN.1 modules/declarations from different RFCs, f.e.
[SubjectPublicKeyInfo][SubjectPublicKeyInfo] from [RFC5280][RFC5280] and [PrivateKeyInfo][PrivateKeyInfo] from [RFC5208][RFC5208]

[SubjectPublicKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-subject-public-key-info/index.html

[PrivateKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-private-key-info/index.html

[RFC5280]: https://datatracker.ietf.org/doc/html/rfc5280

[RFC5208]: https://datatracker.ietf.org/doc/html/rfc5208

# Module cryptography-provider-apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CommonCrypto][CommonCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

# Package dev.whyoleg.cryptography.providers.apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CommonCrypto][CommonCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

# Module cryptography-provider-base

Shared implementation details for providers

# Module cryptography-provider-cryptokit

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CryptoKit][CryptoKit]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptoKit]: https://developer.apple.com/documentation/cryptokit/

# Package dev.whyoleg.cryptography.providers.cryptokit

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CryptoKit][CryptoKit]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptoKit]: https://developer.apple.com/documentation/cryptokit/

# Module cryptography-provider-jdk

Provides implementation of [CryptographyProvider][CryptographyProvider] via JDK built-in [JCA][JCA]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[JCA]: https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html

# Package dev.whyoleg.cryptography.providers.jdk

Provides implementation of [CryptographyProvider][CryptographyProvider] via JDK built-in [JCA][JCA]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[JCA]: https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html

# Module cryptography-provider-openssl3-api

Provides implementation of [CryptographyProvider][CryptographyProvider] via [OpenSSL 3.x][OpenSSL 3.x]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[OpenSSL 3.x]: https://www.openssl.org

# Package dev.whyoleg.cryptography.providers.openssl3

Provides implementation of [CryptographyProvider][CryptographyProvider] via [OpenSSL 3.x][OpenSSL 3.x].

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[OpenSSL 3.x]: https://www.openssl.org

# Module cryptography-provider-webcrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via [WebCrypto][WebCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

# Package dev.whyoleg.cryptography.providers.webcrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via [WebCrypto][WebCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
