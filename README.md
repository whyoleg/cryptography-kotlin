# cryptography-kotlin

Type-safe Multiplatform cryptography library for Kotlin

```kotlin
CryptographyProvider.Default
    .get(SHA512)
    .hasher()
    .hash("Kotlin is Awesome".encodeToByteArray())
```

Detailed documentation can be found on
[project website](https://whyoleg.github.io/cryptography-kotlin/) as well as in
[API reference](https://whyoleg.github.io/cryptography-kotlin/api/)

## Overview

cryptography-kotlin provides multiplatform API which consists of multiple components:

* [Secure random][Secure random] with [kotlin.Random][kotlin.Random] like API which can be used independently of other modules
* common API to use different cryptography operations, like [ciphers][ciphers], [digests][digests] and [signatures][signatures]
* multiple algorithms definitions, like [AES][AES], [RSA][RSA], [ECDSA][ECDSA] and [SHA][SHA]
* multiple cryptography [providers][providers], like [OpenSSL][OpenSSL], [WebCrypto][WebCrypto] and [JDK][JDK]

The library doesn't implement any cryptography algorithm on its own, but wraps well-known future-proof solutions
like [OpenSSL 3.x](https://www.openssl.org), [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
or [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
with type-safe multiplatform API providing uniform experience with aligned default behavior,
and same expected results using identical parameters while allowing to use platform-specific capabilities.
For supported algorithms, primitives and targets, please consult [Providers documentation][providers]

## Using in your projects

Make sure that you use Kotlin 1.8.10+.
Additionally, it's possible to use [BOM][BOM] or [Gradle version catalog][Gradle version catalog] to add dependencies easier

```kotlin
repositories {
    mavenCentral()
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.1.0")
    // some provider
    implementation("dev.whyoleg.cryptography:cryptography-jdk:0.1.0")
}
```

<details>
<summary>Snapshots of the development version are available in Sonatype's snapshot repository.</summary>
<p>

```kotlin
repositories {
    maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.2.0-SNAPSHOT")
    // some provider
    implementation("dev.whyoleg.cryptography:cryptography-jdk:0.2.0-SNAPSHOT")
}
```

</p>
</details>

## Bugs and Feedback

For bugs, questions and discussions, please use the [GitHub Issues](https://github.com/whyoleg/cryptography-kotlin/issues)

## License

    Copyright 2023 Oleg Yukhnevich.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

[Secure random]: https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-random

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[ciphers]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.cipher/index.html

[digests]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.hash/index.html

[signatures]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.signature/index.html

[AES]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.symmetric/-a-e-s/index.html

[RSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.asymmetric/-r-s-a/index.html

[ECDSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.asymmetric/-e-c-d-s-a/index.html

[SHA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.digest/index.html

[providers]: https://whyoleg.github.io/cryptography-kotlin/providers/

[OpenSSL]: https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-openssl3/

[WebCrypto]: https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-webcrypto/

[JDK]: https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-jdk/

[BOM]: https://whyoleg.github.io/cryptography-kotlin/bom/

[Gradle version catalog]: https://whyoleg.github.io/cryptography-kotlin/gradle-version-catalog/
