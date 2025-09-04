# CryptoKit

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CryptoKit][CryptoKit]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* KeyFormat: doesn't support `JWK` key format yet
* AES.GCM supports only a default tag size of 96 bits
* EdDSA/XDH: CryptoKit supports only Ed25519 and X25519. DER/PEM and RAW key encodings are available via the provider APIs.

## Example

```kotlin
val provider = CryptographyProvider.CryptoKit // or CryptographyProvider.Default 

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-cryptokit:0.5.0")
}
```

[CryptographyProvider]: ../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptoKit]: https://developer.apple.com/documentation/cryptokit/

[Supported primitives section]: index.md#supported-primitives
