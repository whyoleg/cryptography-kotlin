# JDK

The JDK provider wraps Java's built-in [JCA][JCA] and is the default for JVM targets.

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-jdk:0.5.0")
}
```

Access via `CryptographyProvider.JDK` (available on JVM targets only).

### Custom Java providers

In addition to this, there is a possibility to create [CryptographyProvider][CryptographyProvider]
from [java.util.Provider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Provider.html), f.e.
using [BouncyCastle](https://www.bouncycastle.org):

```kotlin
// any other JCA provider could be used
val provider = CryptographyProvider.JDK(BouncyCastleProvider())

// get some algorithm which not supported on a JDK version or platform (in case of Android)
provider.get(SHA512)
```

## Android support

JDK provider is also tested via Android emulator on API level 35.
Supported algorithms on Android highly depend on Android API level and used provider.

For better compatibility, you can use [BouncyCastle](https://www.bouncycastle.org) provider as shown
in [BouncyCastle](#bouncycastle).

## BouncyCastle

Some algorithms or parameters may not be supported by the default JDK provider depending on JDK version
or platform (e.g., Android). The library provides an ability to use [BouncyCastle](https://www.bouncycastle.org)
as the default provider via an additional dependency:

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-jdk-bc:0.5.0")
}
```

---

See the [algorithm support tables](../../primitives/operations/index.md) for specific limitations
and [Working with Keys](../../primitives/keys.md#key-formats) for key format restrictions.

[CryptographyProvider]: ../../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[JCA]: https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html
