package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Encryptor {
    public fun ciphertextSize(plaintextSize: Int): Int

    public interface Provider<P> {
        public val defaultParameters: P

        public fun syncEncryptor(parameters: P = defaultParameters): SyncEncryptor
        public fun asyncEncryptor(parameters: P = defaultParameters): AsyncEncryptor
        public fun encryptFunction(parameters: P = defaultParameters): EncryptFunction
    }
}

public interface SyncEncryptor : Encryptor {
    public fun encrypt(plaintextInput: Buffer): Buffer
    public fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}

public interface AsyncEncryptor : Encryptor {
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}


//TODO!!!
public interface BoxedEncryptor<B : Any> {
    public fun ciphertextSize(plaintextSize: Int): Int
    public fun encrypt(plaintextInput: Buffer): B
    public fun encrypt(plaintextInput: Buffer, boxOutput: B): B
}
