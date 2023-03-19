# WebCrypto

> [API Reference](https://whyoleg.github.io/cryptography-kotlin/api/cryptography-webcrypto/index.html)

## Limitations

* AES.* (browser only): may not support `192 bit` keys
* AES.CBC: only `padding=true` is supported
* ECDSA: only `RAW` signature format is supported
* ECDSA (browser only): private key `DER` encoding can be different comparing to other providers
  (though it will still work)
