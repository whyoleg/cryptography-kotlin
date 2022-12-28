@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias SignatureVerifierProvider<P> = CryptographyOperationProvider<P, SignatureVerifier>
public typealias SignatureVerifierFactory<P> = CryptographyOperationFactory<P, SignatureVerifier>

public interface SignatureVerifier : CryptographyOperation {
    public val signatureSize: Int
    public suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean
    public fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean
}
