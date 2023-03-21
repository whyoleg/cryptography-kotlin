# Module cryptography-jdk

Provides implementation of [CryptographyProvider][CryptographyProvider] via JDK built-in [JCA][JCA]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* ECDSA: only `DER` signature format is supported for java < 9
* KeyFormat: doesn't support `JWK` key format yet

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

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.provider/-cryptography-provider/index.html

[JCA]: https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives

# Package dev.whyoleg.cryptography.jdk

Provides implementation of [CryptographyProvider][CryptographyProvider] via JDK built-in [JCA][JCA]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.provider/-cryptography-provider/index.html

[JCA]: https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives
