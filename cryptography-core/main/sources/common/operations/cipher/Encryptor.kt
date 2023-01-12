package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public fun encryptBlocking(plaintextInput: Buffer): Buffer
}
