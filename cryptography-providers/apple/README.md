# Module cryptography-provider-apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CommonCrypto][CommonCrypto]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* KeyFormat: doesn't support `JWK` key format yet
* EC.PrivateKey:
    * `DER`, `PEM`, `DER.SEC1`, `PEM.SEC1`:
      to decode, `publicKey` field should be present in `EcPrivateKey` structure specified
      in [RFC5915](https://datatracker.ietf.org/doc/html/rfc5915).
      Not all implementations in the wild include this field, as it's optional.
    * `RAW`: encoding is supported, but decoding is not supported
* EC.PublicKey:
    * `RAW.Compressed` key format is not supported

## Example

```kotlin
val provider = CryptographyProvider.Apple // or CryptographyProvider.Default 

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-apple:0.4.0")
}
```

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives

# Package dev.whyoleg.cryptography.providers.apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CommonCrypto][CommonCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives
