package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean
    public fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean
}
