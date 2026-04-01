# Apple

On Apple platforms, the library provides two provider implementations:

* **CryptoKit** -- the modern, preferred provider via [CryptoKit][CryptoKit]
* **CommonCrypto** -- the legacy fallback via [CommonCrypto][CommonCrypto]

!!! warning "Non-default Xcode location"

    The CryptoKit provider requires Swift and links against Swift libraries shipped with Xcode.
    If Xcode is **not** installed at `/Applications/Xcode.app` (e.g. you use multiple Xcode versions
    or a tool like [xcodes](https://github.com/XcodesOrg/xcodes)), you may see linker errors at
    build time.
    See [Xcode / Swift compatibility](../../getting-started/troubleshooting/xcode-compatibility.md)
    for how to fix this.

## Using in your projects

```kotlin
dependencies {
    // for cryptokit
    implementation("dev.whyoleg.cryptography:cryptography-provider-cryptokit:0.6.0")
    // for commoncrypto
    implementation("dev.whyoleg.cryptography:cryptography-provider-apple:0.6.0")
}
```

Access via `CryptographyProvider.CryptoKit` and `CryptographyProvider.Apple` correspondingly (available on iOS, macOS, watchOS, tvOS).

---

See the [algorithm support tables](../../primitives/operations/index.md) for specific limitations
and [Working with Keys](../../primitives/keys.md#key-formats) for key format restrictions.

[CryptoKit]: https://developer.apple.com/documentation/cryptokit/

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

[CryptographyProvider]: ../../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html
