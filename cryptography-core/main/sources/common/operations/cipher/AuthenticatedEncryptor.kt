package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    override suspend fun encrypt(plaintextInput: Buffer): Buffer = encrypt(null, plaintextInput)
    public fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    override fun encryptBlocking(plaintextInput: Buffer): Buffer = encryptBlocking(null, plaintextInput)
}
