# JDK

Provides implementation of [CryptographyProvider][CryptographyProvider] via JDK built-in [JCA][JCA]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* KeyFormat: doesn't support `JWK` key format yet

## Example

```kotlin
val provider = CryptographyProvider.JDK // or CryptographyProvider.Default

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-jdk:0.5.0")
}
```

## Custom Java providers

Some specific algorithms (SHA3 family of digests on JDK 8) or parameters (`secp256k1` curve for ECDSA) could be not supported by default JDK
provider, but it doesn't mean, that you cannot use them with `cryptography-kotlin`.
There is a possibility to create [CryptographyProvider][CryptographyProvider]
from [java.util.Provider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Provider.html), f.e.
using [BouncyCastle](https://www.bouncycastle.org):

```kotlin
val provider = CryptographyProvider.JDK(BouncyCastleProvider())

// get some algorithm which not supported on a JDK version or platform (in case of Android)
provider.get(SHA512)
```

The library provides an ability to configure the default security provider used by JDK provider via
[DefaultJdkSecurityProvider][DefaultJdkSecurityProvider].
In addition to that, it's possible to use [BouncyCastle](https://www.bouncycastle.org) as the default provider via an additional dependency:

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-jdk-bc:0.5.0")
}
```

## Android support

JDK provider is also tested via Android emulator on API level 21, 27 and 33.
Supported algorithms on Android highly depend on Android API level and used provider.
Some limitations are:

* default provider doesn't support `RSA-SSA-PSS` or `SHA3` algorithms

For better compatibility, you can use [BouncyCastle](https://www.bouncycastle.org) provider as shown
in [Custom Java providers](#custom-java-providers).

[CryptographyProvider]: ../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[DefaultJdkSecurityProvider]: ../api/cryptography-provider-jdk/dev.whyoleg.cryptography.providers.jdk/-default-jdk-security-provider/index.html

[JCA]: https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html

[Supported primitives section]: index.md#supported-primitives
