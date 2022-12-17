package dev.whyoleg.cryptography.cipher

public interface DecryptorProvider<P> {
    public val defaultDecryptParameters: P
    public fun syncDecryptor(parameters: P = defaultDecryptParameters): SyncDecryptor
    public fun asyncDecryptor(parameters: P = defaultDecryptParameters): AsyncDecryptor
    public fun decryptFunction(parameters: P = defaultDecryptParameters): DecryptFunction
}
