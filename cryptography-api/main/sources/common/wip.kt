package dev.whyoleg.cryptography.api

public interface AeadSyncEncryptor {
    public fun ciphertextSize(plaintextSize: Int): Int

    public fun encrypt(associatedData: ByteArray?, plaintextInput: ByteArray): ByteArray
    public fun encrypt(associatedData: ByteArray?, plaintextInput: ByteArray, ciphertextOutput: ByteArray): ByteArray
}

public interface SyncEncryptor {
    public fun ciphertextSize(plaintextSize: Int): Int

    public fun encrypt(plaintextInput: ByteArray): ByteArray
    public fun encrypt(plaintextInput: ByteArray, ciphertextOutput: ByteArray): ByteArray
}

public interface AsyncEncryptor {
    public fun ciphertextSize(plaintextSize: Int): Int

    public suspend fun encrypt(plaintextInput: ByteArray): ByteArray
    public suspend fun encrypt(plaintextInput: ByteArray, ciphertextOutput: ByteArray): ByteArray
}

public interface StreamEncryptor {
    public fun createEncryptFunction(): EncryptFunction
}

public interface EncryptFunction { //: Closeable
    public fun ciphertextPartSize(plaintextPartSize: Int): Int
    public fun encryptPart(plaintextInput: ByteArray): ByteArray
    public fun encryptPart(plaintextInput: ByteArray, ciphertextOutput: ByteArray): ByteArray

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: Int): Int
    public fun encryptFinalPart(plaintextInput: ByteArray): ByteArray
    public fun encryptFinalPart(plaintextInput: ByteArray, ciphertextOutput: ByteArray): ByteArray
}

public interface SyncBoxedEncryptor<B : Any> {
    public fun ciphertextSize(plaintextSize: Int): Int

    public fun encryptBoxed(plaintextInput: ByteArray): B
    public fun encryptBoxed(plaintextInput: ByteArray, ciphertextOutput: B): B
}

public interface AsyncBoxedEncryptor<B : Any> {
    public fun ciphertextSize(plaintextSize: Int): Int

    public suspend fun encryptBoxed(plaintextInput: ByteArray): B
    public suspend fun encryptBoxed(plaintextInput: ByteArray, ciphertextOutput: B): B
}
