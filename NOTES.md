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
