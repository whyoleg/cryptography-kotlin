package dev.whyoleg.cryptography.cipher

public interface EncryptorProvider<P> {
    public val defaultEncryptorParameters: P
    public fun syncEncryptor(parameters: P = defaultEncryptorParameters): SyncEncryptor
    public fun asyncEncryptor(parameters: P = defaultEncryptorParameters): AsyncEncryptor
    public fun encryptFunction(parameters: P = defaultEncryptorParameters): EncryptFunction
}
