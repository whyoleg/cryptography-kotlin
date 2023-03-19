# cryptography-kotlin

Type-safe Multiplatform cryptography library for Kotlin

```kotlin
CryptographyProvider.Default
    .get(SHA512)
    .hasher()
    .hash("Kotlin is Awesome".encodeToByteArray())
```

## Modules

* [random](https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-random/) - zero-dependency platform-dependent CSPRNG
* [core](https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-core) - core interfaces for implementation by providers
* providers:
    * [jdk](https://whyoleg.github.io/cryptography-kotlin/providers/jdk/) - based on
      JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
      (javax.crypto.* / java.security.*)
    * [webcrypto](https://whyoleg.github.io/cryptography-kotlin/providers/webcrypto/) - based on
      [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
    * [apple](https://whyoleg.github.io/cryptography-kotlin/providers/apple/) - based on
      [CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html)
    * [openssl3](https://whyoleg.github.io/cryptography-kotlin/providers/openssl3/) - based on
      [OpenSSL 3.x](https://www.openssl.org), statically linked to prebuilt OpenSSL 3.0.8 or dynamically linked (experimental)
* [bom](https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-bom) and
  [version-catalog](https://whyoleg.github.io/cryptography-kotlin/modules/cryptography-version-catalog) -
  provides [Maven BOM](https://docs.gradle.org/current/userguide/platforms.html#sub:bom_import)
  and [Gradle version catalog](https://docs.gradle.org/current/userguide/platforms.html#sec:importing-published-catalog)
  artifacts respectively

## Documentation

* [Project website with detailed documentation](https://whyoleg.github.io/cryptography-kotlin/)
* [Full cryptography-kotlin API reference](https://whyoleg.github.io/cryptography-kotlin/api/)

## Using in your projects

Make sure, that you use Kotlin 1.8.10+

> ⚠️ NOT YET PUBLISHED TO MAVEN CENTRAL

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
<summary>Snapshots of the development version are available in Sonatype's snapshots repository.</summary>
<p>

```kotlin
repositories {
    maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.1.0-SNAPSHOT")
    // some provider
    implementation("dev.whyoleg.cryptography:cryptography-jdk:0.1.0-SNAPSHOT")
}
```

</p>
</details>

## Bugs and Feedback

For bugs, questions and discussions please use the [Github Issues](https://github.com/whyoleg/cryptography-kotlin/issues).

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
