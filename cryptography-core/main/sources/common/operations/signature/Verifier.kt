package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias VerifierProvider<P> = CryptographyOperationProvider<P, Verifier>
public typealias VerifierFactory<P> = CryptographyOperationFactory<P, Verifier>

public interface Verifier : CryptographyOperation {
    public val signatureSize: Int
    public suspend fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean
    public fun verifyBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean
    public fun verifyFunction(): VerifyFunction
}
