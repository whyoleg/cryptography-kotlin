package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public suspend fun generateSignature(dataInput: Buffer): Buffer
    public fun generateSignatureBlocking(dataInput: Buffer): Buffer
}
