# WebCrypto

The WebCrypto provider wraps the [W3C WebCrypto API][WebCrypto] and is the default for JS and WASM targets.

!!! note "Suspend functions only"

    The WebCrypto API is asynchronous by default. Because of this, the WebCrypto provider only supports
    `suspend` functions. Calling `Blocking` variants (e.g., `encryptBlocking()`, `generateKeyBlocking()`)
    will throw an exception.

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-webcrypto:0.6.0")
}
```

Access via `CryptographyProvider.WebCrypto` (available on js, wasmJs targets).

---

See the [algorithm support tables](../../primitives/operations/index.md) for specific limitations
and [Working with Keys](../../primitives/keys.md#key-formats) for key format restrictions.

[CryptographyProvider]: ../../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
