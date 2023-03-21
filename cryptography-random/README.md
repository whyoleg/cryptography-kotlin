# Module cryptography-random

Provides [CryptographyRandom][CryptographyRandom] zero-dependency platform-dependent CSPRNG exposed via [kotlin.Random][kotlin.Random] API

Depending on target/platform uses:

* jvm - [SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html)
* js - [Crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
* darwin(macos, ios) -
  [CCRandomGenerateBytes](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonRandom.h.auto.html)
* linux - [getrandom](https://man7.org/linux/man-pages/man2/getrandom.2.html) with fallback
  to [urandom](https://en.wikipedia.org/wiki//dev/random)
* mingw - [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)

## Example

```kotlin
val bytes: ByteArray = CryptographyRandom.nextBytes(20)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-random:0.1.0")
}
```

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[CryptographyRandom]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-kotlin/api/cryptography-random/dev.whyoleg.cryptography.random/-cryptography-random/index.html

# Package dev.whyoleg.cryptography.random

Provides [CryptographyRandom][CryptographyRandom] zero-dependency platform-dependent CSPRNG exposed via [kotlin.Random][kotlin.Random] API

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[CryptographyRandom]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-kotlin/api/cryptography-random/dev.whyoleg.cryptography.random/-cryptography-random/index.html
