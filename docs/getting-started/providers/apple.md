# Apple

On Apple platforms, the library provides two provider implementations:

* **CryptoKit** — the modern, preferred provider via [CryptoKit][CryptoKit]
* **CommonCrypto** — the legacy fallback via [CommonCrypto][CommonCrypto]

## CryptoKit

### Limitations

* AES.GCM supports only a default tag size of 96 bits
* EdDSA/XDH: supports only Ed25519 and X25519

### Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-cryptokit:0.5.0")
}
```

Access via `CryptographyProvider.CryptoKit` (available on iOS, macOS, watchOS, tvOS).

## CommonCrypto

### Limitations

* EC.PrivateKey:
    * `DER`, `PEM`, `DER.SEC1`, `PEM.SEC1`:
      to decode, `publicKey` field should be present in `EcPrivateKey` structure specified
      in [RFC5915](https://datatracker.ietf.org/doc/html/rfc5915).
      Not all implementations in the wild include this field, as it's optional.
    * `RAW`: encoding is supported, but decoding is not supported
* EC.PublicKey:
    * `RAW.Compressed` key format is not supported

### Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-apple:0.5.0")
}
```

Access via `CryptographyProvider.Apple` (available on iOS, macOS, watchOS, tvOS).

[CryptoKit]: https://developer.apple.com/documentation/cryptokit/

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

[CryptographyProvider]: ../../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html
