## Parameterized/Box cipher

```kotlin
//aes gcm: P=IV, B=IV,TAG
//aes cbc: P=IV, B=IV
public interface ParameterizedEncryptor<P, B> {
    public suspend fun encrypt(plaintextInput: Buffer, associatedData: Buffer?): Buffer
    public suspend fun encryptWith(parameters: P, plaintextInput: Buffer, associatedData: Buffer?): Buffer
    public suspend fun encryptBox(plaintextInput: Buffer, associatedData: Buffer?): B
    public suspend fun encryptBoxWith(parameters: P, plaintextInput: Buffer, associatedData: Buffer?): B
}


public interface ParameterizedDecryptor<P, B> {
    public suspend fun decrypt(ciphertextInput: Buffer, associatedData: Buffer?): Buffer
    public suspend fun decryptWith(parameters: P, ciphertextInput: Buffer, associatedData: Buffer?): Buffer
    public suspend fun decryptBox(ciphertextInput: B, associatedData: Buffer?): Buffer
    public suspend fun decryptBoxWith(parameters: P, ciphertextInput: B, associatedData: Buffer?): Buffer
}
```

## key management

- https://github.com/tersesystems/securitybuilder

## default openssl provider parameters

- https://www.openssl.org/docs/man3.0/man7/OSSL_PROVIDER-default.html

## current plan:

1. introduce bigint module and migration RSA publicExponent to BigInt
2. introduce PEM module and migrate usages
3. introduce DER module and implement RSA keys in Apple and other providers
4. introduce JOSE module and implement JWK keys in all providers
5. ECDSA support in Apple provider
6. Done!

## BigInt implementation

BigInt todo:

* Operators (+-/* etc)
* benchmarks for different operations
* BigIntRange
* exact variants
* Random.nextBigInt?
* align exceptions, validation, error messages
