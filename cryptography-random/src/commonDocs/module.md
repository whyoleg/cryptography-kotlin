# Module cryptography-random

Zero-dependency platform-dependent CSPRNG exposed via [kotlin.Random][kotlin.Random] API.

The module provides [CryptographyRandom][CryptographyRandom] which uses
platform-native secure random sources:

- JVM: [SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html)
- JS, WasmJs: [Crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
- WasmWasi: [random_get](https://wasix.org/docs/api-reference/wasi/random_get)
- Apple: [CCRandomGenerateBytes](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonRandom.h.auto.html)
- Linux: [getrandom](https://man7.org/linux/man-pages/man2/getrandom.2.html)
- Mingw: [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)

#### [Get complete dependency details at klibs.io](https://klibs.io/package/dev.whyoleg.cryptography/cryptography-random)

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[CryptographyRandom]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-random/dev.whyoleg.cryptography.random/-cryptography-random/index.html

# Package dev.whyoleg.cryptography.random

Zero-dependency platform-dependent CSPRNG exposed via [kotlin.Random][kotlin.Random] API.

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/
