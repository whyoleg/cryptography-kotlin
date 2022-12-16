package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Decryptor {
    public fun plaintextSize(ciphertextSize: Int): Int
}

public interface SyncDecryptor : Decryptor {
    public fun decrypt(ciphertextInput: Buffer): Buffer
    public fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
}

public interface AeadSyncDecryptor : SyncDecryptor {
    public fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    public fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    override fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(null, ciphertextInput)
    override fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = decrypt(null, ciphertextInput, plaintextOutput)
}

public interface AsyncDecryptor : Decryptor {
    public suspend fun decrypt(ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
}

public interface AeadAsyncDecryptor : AsyncDecryptor {
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    override suspend fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(null, ciphertextInput)
    override suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = decrypt(null, ciphertextInput, plaintextOutput)
}

public interface DecryptFunction : Closeable {
    public fun plaintextPartSize(ciphertextPartSize: Int): Int
    public fun decryptPart(ciphertextPartInput: Buffer): Buffer
    public fun decryptPart(ciphertextPartInput: Buffer, plaintextPartOutput: Buffer): Buffer

    public fun plaintextFinalPartSize(ciphertextFinalPartSize: Int): Int
    public fun decryptFinalPart(ciphertextFinalPartInput: Buffer): Buffer
    public fun decryptFinalPart(ciphertextFinalPartInput: Buffer, plaintextFinalPartOutput: Buffer): Buffer
}

public interface AeadDecryptFunction : DecryptFunction {
    //TODO: naming?
    public fun putAssociatedData(associatedData: Buffer)
}
