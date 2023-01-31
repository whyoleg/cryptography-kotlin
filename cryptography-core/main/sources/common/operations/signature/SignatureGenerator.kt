package dev.whyoleg.cryptography.operations.signature


import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public suspend fun generateSignature(dataInput: ByteArray): ByteArray = generateSignatureBlocking(dataInput)
    public fun generateSignatureBlocking(dataInput: ByteArray): ByteArray
}
