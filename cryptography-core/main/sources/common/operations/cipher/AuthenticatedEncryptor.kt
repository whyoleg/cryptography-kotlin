package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(plaintextInput: Buffer, associatedData: Buffer?): Buffer
    override suspend fun encrypt(plaintextInput: Buffer): Buffer = encrypt(plaintextInput, null)
    public fun encryptBlocking(plaintextInput: Buffer, associatedData: Buffer?): Buffer
    override fun encryptBlocking(plaintextInput: Buffer): Buffer = encryptBlocking(plaintextInput, null)
}
