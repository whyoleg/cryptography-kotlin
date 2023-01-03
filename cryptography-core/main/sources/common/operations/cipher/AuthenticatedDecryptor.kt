package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface AuthenticatedDecryptor : Decryptor {
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    override suspend fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(null, ciphertextInput)
    public fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = decryptBlocking(null, ciphertextInput)
}
