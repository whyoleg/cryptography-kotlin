package dev.whyoleg.cryptography

import dev.whyoleg.vio.*

public interface BaseDecryptor

public interface SyncDecryptor : BaseDecryptor {
    public fun plaintextSize(ciphertextSize: BinarySize): BinarySize

    public fun decrypt(ciphertextInput: Ciphertext): Plaintext
    public fun decrypt(ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext
}

public interface AsyncDecryptor : BaseDecryptor {
    public fun plaintextSize(ciphertextSize: BinarySize): BinarySize

    public suspend fun decryptAsync(ciphertextInput: Ciphertext): Plaintext
    public suspend fun decryptAsync(ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext
}

public interface StreamDecryptor : BaseDecryptor {
    public fun createDecryptFunction(): DecryptFunction
}

public inline fun <R> StreamDecryptor.decrypt(block: DecryptFunction.() -> R): R {
    return createDecryptFunction().use(block)
}

public interface DecryptFunction : Closeable {
    public fun plaintextPartSize(plaintextPartSize: BinarySize): BinarySize
    public fun decryptPart(ciphertextInput: Ciphertext): Plaintext
    public fun decryptPart(ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext

    public fun plaintextFinalPartSize(plaintextFinalPartSize: BinarySize): BinarySize
    public fun decryptFinalPart(ciphertextInput: Ciphertext): Plaintext
    public fun decryptFinalPart(ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext
}

//TODO: decide on outputs and it sizes
public interface BaseBoxedDecryptor<B : CipherBox>

public interface SyncBoxedDecryptor<B : CipherBox> : BaseBoxedDecryptor<B> {
    public fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize

    public fun decryptBoxed(ciphertextInput: B): Plaintext
    public fun decryptBoxed(ciphertextInput: B, plaintextOutput: Plaintext): Plaintext
}

public interface AsyncBoxedDecryptor<B : CipherBox> : BaseBoxedDecryptor<B> {
    public fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize

    public suspend fun decryptBoxedAsync(ciphertextInput: B): Plaintext
    public suspend fun decryptBoxedAsync(ciphertextInput: B, plaintextOutput: Plaintext): Plaintext
}
