package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public suspend fun decrypt(ciphertextInput: Buffer): Buffer
    public fun decryptBlocking(ciphertextInput: Buffer): Buffer
}
