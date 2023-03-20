# Module cryptography-jdk

Provides implementation of [CryptographyProvider][CryptographyProvider] via
JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
(javax.crypto.* / java.security.*)

## Example

```kotlin
val provider = CryptographyProvider.JDK

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-jdk:0.1.0")
}
```

# Package dev.whyoleg.cryptography.jdk

Provides implementation of [CryptographyProvider][CryptographyProvider] via
JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
(javax.crypto.* / java.security.*)

<!--- MODULE cryptography-jdk -->

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.provider/-cryptography-provider/index.html

<!--- END -->
