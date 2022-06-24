package dev.whyoleg.cryptography

import dev.whyoleg.vio.*

public interface BaseAeadDecryptor

public interface SyncAeadDecryptor : BaseAeadDecryptor {
    public fun plaintextSize(ciphertextSize: BinarySize): BinarySize

    public fun decrypt(associatedData: AssociatedData, ciphertextInput: Ciphertext): Plaintext
    public fun decrypt(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext,
        plaintextOutput: Plaintext
    ): Plaintext
}

public interface AsyncAeadDecryptor : BaseAeadDecryptor {
    public fun plaintextSize(ciphertextSize: BinarySize): BinarySize

    public suspend fun decryptAsync(associatedData: AssociatedData, ciphertextInput: Ciphertext): Plaintext
    public suspend fun decryptAsync(
        associatedData: AssociatedData,
        ciphertextInput: Ciphertext,
        plaintextOutput: Plaintext
    ): Plaintext
}

public interface StreamAeadDecryptor : BaseAeadDecryptor {
    public fun createDecryptFunction(associatedData: AssociatedData): DecryptFunction
}

public inline fun <R> StreamAeadDecryptor.decrypt(associatedData: AssociatedData, block: DecryptFunction.() -> R): R {
    return createDecryptFunction(associatedData).use(block)
}

//TODO: decide on outputs and it sizes
public interface BaseBoxedAeadDecryptor<B : CipherBox>

public interface SyncBoxedAeadDecryptor<B : CipherBox> : BaseBoxedAeadDecryptor<B> {
    public fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize

    public fun decryptBoxed(associatedData: AssociatedData, ciphertextInput: B): Plaintext
    public fun decryptBoxed(associatedData: AssociatedData, ciphertextInput: B, plaintextOutput: Plaintext): Plaintext
}

public interface AsyncBoxedAeadDecryptor<B : CipherBox> : BaseBoxedAeadDecryptor<B> {
    public fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize

    public suspend fun decryptBoxedAsync(associatedData: AssociatedData, ciphertextInput: B): Plaintext
    public suspend fun decryptBoxedAsync(
        associatedData: AssociatedData,
        ciphertextInput: B,
        plaintextOutput: Plaintext
    ): Plaintext
}
