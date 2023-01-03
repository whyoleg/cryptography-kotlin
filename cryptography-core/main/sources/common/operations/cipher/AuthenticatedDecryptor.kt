package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface AuthenticatedDecryptor : Decryptor {
    public suspend fun decrypt(ciphertextInput: Buffer, associatedData: Buffer?): Buffer
    override suspend fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(ciphertextInput, null)
    public fun decryptBlocking(ciphertextInput: Buffer, associatedData: Buffer?): Buffer
    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = decryptBlocking(ciphertextInput, null)
}
