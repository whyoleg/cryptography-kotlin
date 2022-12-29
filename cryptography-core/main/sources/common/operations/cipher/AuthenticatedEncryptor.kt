package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    override suspend fun encrypt(plaintextInput: Buffer): Buffer = encrypt(null, plaintextInput)
    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = encrypt(null, plaintextInput, ciphertextOutput)
    public fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    public fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    override fun encryptBlocking(plaintextInput: Buffer): Buffer = encryptBlocking(null, plaintextInput)
    override fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer =
        encryptBlocking(null, plaintextInput, ciphertextOutput)

}
