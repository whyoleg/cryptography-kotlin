# WebCrypto

The WebCrypto provider wraps the [W3C WebCrypto API][WebCrypto] and is the default for JS and WASM targets.

## Limitations

* only `suspend` functions are supported, because `WebCrypto` API is async by default
* AES.* (browser only): may not support `192 bit` keys
* AES.CBC: only `padding=true` is supported
* EdDSA/XDH:
    * supports only Ed25519 and X25519
    * algorithms were added later to WebCrypto and might not be available in all browsers (https://github.com/w3c/webcrypto/pull/362)
    * (browser only) private key decoding may fail for DER/PEM formats that contain embedded public key

## Using in your projects

If you need the WebCrypto provider explicitly (instead of via `optimal`):

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-webcrypto:0.5.0")
}
```

Access via `CryptographyProvider.WebCrypto` (available on js, wasmJs targets).

[CryptographyProvider]: ../../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
