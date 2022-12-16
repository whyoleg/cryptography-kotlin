package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public interface AeadDecryptor : Decryptor

public interface SyncAeadDecryptor : SyncDecryptor {
    public fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    public fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    override fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(null, ciphertextInput)
    override fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = decrypt(null, ciphertextInput, plaintextOutput)
}

public interface AsyncAeadDecryptor : AsyncDecryptor {
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    override suspend fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(null, ciphertextInput)
    override suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = decrypt(null, ciphertextInput, plaintextOutput)
}
