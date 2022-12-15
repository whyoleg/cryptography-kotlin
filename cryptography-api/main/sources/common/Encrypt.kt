package dev.whyoleg.cryptography.api

public interface Encryptor {
    public fun ciphertextSize(plaintextSize: Int): Int
}

public interface SyncEncryptor : Encryptor {
    public fun encrypt(plaintextInput: Buffer): Buffer
    public fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}

public interface AeadSyncEncryptor : SyncEncryptor {
    public fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    public fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    override fun encrypt(plaintextInput: Buffer): Buffer = encrypt(null, plaintextInput)
    override fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = encrypt(null, plaintextInput, ciphertextOutput)
}

public interface AsyncEncryptor : Encryptor {
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}

public interface AeadAsyncEncryptor : AsyncEncryptor {
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    override suspend fun encrypt(plaintextInput: Buffer): Buffer = encrypt(null, plaintextInput)
    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = encrypt(null, plaintextInput, ciphertextOutput)
}

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: Int): Int
    public fun encryptPart(plaintextPartInput: Buffer): Buffer
    public fun encryptPart(plaintextPartInput: Buffer, ciphertextPartOutput: Buffer): Buffer

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: Int): Int
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer): Buffer
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer, ciphertextFinalPartOutput: Buffer): Buffer
}

public interface AeadEncryptFunction : EncryptFunction {
    //TODO: naming?
    public fun putAssociatedData(associatedData: Buffer)
}

//TODO: have no idea what is the best api for it
public interface BoxedEncryptor<B : Any> {
    public fun ciphertextSize(plaintextSize: Int): Int
    public fun encrypt(plaintextInput: Buffer): B
    public fun encrypt(plaintextInput: Buffer, ciphertextOutput: B): B
}
