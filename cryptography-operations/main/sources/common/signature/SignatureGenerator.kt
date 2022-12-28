@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias SignatureGeneratorProvider<P> = CryptographyOperationProvider<P, SignatureGenerator>
public typealias SignatureGeneratorFactory<P> = CryptographyOperationFactory<P, SignatureGenerator>

public interface SignatureGenerator : CryptographyOperation {
    public val signatureSize: Int
    public suspend fun generateSignature(dataInput: Buffer): Buffer
    public suspend fun generateSignature(dataInput: Buffer, signatureOutput: Buffer): Buffer
    public fun generateSignatureBlocking(dataInput: Buffer): Buffer
    public fun generateSignatureBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer
}
