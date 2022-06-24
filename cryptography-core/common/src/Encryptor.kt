package dev.whyoleg.cryptography

import dev.whyoleg.vio.*

//TODO: AEAD, decryptor, cipher

public interface BaseEncryptor

public interface SyncEncryptor : BaseEncryptor {
    public fun ciphertextSize(plaintextSize: BinarySize): BinarySize

    public fun encrypt(plaintextInput: Plaintext): Ciphertext
    public fun encrypt(plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext
}

public interface AsyncEncryptor : BaseEncryptor {
    public fun ciphertextSize(plaintextSize: BinarySize): BinarySize

    public suspend fun encryptAsync(plaintextInput: Plaintext): Ciphertext
    public suspend fun encryptAsync(plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext
}

public interface StreamEncryptor : BaseEncryptor {
    public fun createEncryptFunction(): EncryptFunction
}

public inline fun <R> StreamEncryptor.encrypt(block: EncryptFunction.() -> R): R {
    return createEncryptFunction().use(block)
}

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: BinarySize): BinarySize
    public fun encryptPart(plaintextInput: Plaintext): Ciphertext
    public fun encryptPart(plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: BinarySize): BinarySize
    public fun encryptFinalPart(plaintextInput: Plaintext): Ciphertext
    public fun encryptFinalPart(plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext
}

//TODO: decide on outputs and it sizes
public interface BaseBoxedEncryptor<B : CipherBox>

public interface SyncBoxedEncryptor<B : CipherBox> : BaseBoxedEncryptor<B> {
    public fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize

    public fun encryptBoxed(plaintextInput: Plaintext): B
    public fun encryptBoxed(plaintextInput: Plaintext, ciphertextOutput: B): B
}

public interface AsyncBoxedEncryptor<B : CipherBox> : BaseBoxedEncryptor<B> {
    public fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize

    public suspend fun encryptBoxedAsync(plaintextInput: Plaintext): B
    public suspend fun encryptBoxedAsync(plaintextInput: Plaintext, ciphertextOutput: B): B
}
