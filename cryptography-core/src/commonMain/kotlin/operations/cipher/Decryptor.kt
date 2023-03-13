package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public suspend fun decrypt(ciphertextInput: ByteArray): ByteArray = decryptBlocking(ciphertextInput)
    public fun decryptBlocking(ciphertextInput: ByteArray): ByteArray
}
