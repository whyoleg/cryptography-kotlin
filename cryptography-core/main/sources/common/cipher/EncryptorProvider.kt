package dev.whyoleg.cryptography.cipher

public interface EncryptorProvider<P> {
    public val defaultEncryptParameters: P
    public fun syncEncryptor(parameters: P = defaultEncryptParameters): SyncEncryptor
    public fun asyncEncryptor(parameters: P = defaultEncryptParameters): AsyncEncryptor
    public fun encryptFunction(parameters: P = defaultEncryptParameters): EncryptFunction
}
