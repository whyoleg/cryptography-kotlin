package dev.whyoleg.cryptography

import dev.whyoleg.vio.*

//TODO: AEAD, decryptor, cipher

public interface BaseAeadEncryptor

public interface SyncAeadEncryptor : BaseAeadEncryptor {
    public fun ciphertextSize(plaintextSize: BinarySize): BinarySize

    public fun encrypt(associatedData: AssociatedData, plaintextInput: Plaintext): Ciphertext
    public fun encrypt(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: Ciphertext
    ): Ciphertext
}

public interface AsyncAeadEncryptor : BaseAeadEncryptor {
    public fun ciphertextSize(plaintextSize: BinarySize): BinarySize

    public suspend fun encryptAsync(associatedData: AssociatedData, plaintextInput: Plaintext): Ciphertext
    public suspend fun encryptAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: Ciphertext
    ): Ciphertext
}

public interface StreamAeadEncryptor : BaseAeadEncryptor {
    public fun createEncryptFunction(associatedData: AssociatedData): EncryptFunction
}

public inline fun <R> StreamAeadEncryptor.encrypt(associatedData: AssociatedData, block: EncryptFunction.() -> R): R {
    return createEncryptFunction(associatedData).use(block)
}

//TODO: decide on outputs and it sizes
public interface BaseBoxedAeadEncryptor<B : CipherBox>

public interface SyncBoxedAeadEncryptor<B : CipherBox> : BaseBoxedAeadEncryptor<B> {
    public fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize

    public fun encryptBoxed(associatedData: AssociatedData, plaintextInput: Plaintext): B
    public fun encryptBoxed(associatedData: AssociatedData, plaintextInput: Plaintext, ciphertextOutput: B): B
}

public interface AsyncBoxedAeadEncryptor<B : CipherBox> : BaseBoxedAeadEncryptor<B> {
    public fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize

    public suspend fun encryptBoxedAsync(associatedData: AssociatedData, plaintextInput: Plaintext): B
    public suspend fun encryptBoxedAsync(
        associatedData: AssociatedData,
        plaintextInput: Plaintext,
        ciphertextOutput: B
    ): B
}
