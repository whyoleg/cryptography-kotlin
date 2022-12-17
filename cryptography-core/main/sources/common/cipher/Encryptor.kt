package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Encryptor {
    public fun ciphertextSize(plaintextSize: Int): Int
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
