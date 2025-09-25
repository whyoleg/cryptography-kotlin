package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AesCmacWithIvCipher : AesCmacWithIvEncryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AesCmacWithIvEncryptor {
    public fun initialize()

    @DelicateCryptographyApi
    public suspend fun process(input: ByteArray, iv: ByteArray): ByteArray = processBlocking(input, iv)

    @DelicateCryptographyApi
    public fun processBlocking(input: ByteArray, iv: ByteArray): ByteArray

    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray = encryptWithIvBlocking(iv, plaintext)

    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray
}