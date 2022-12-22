package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias SignerProvider<P> = CryptographyOperationProvider<P, Signer>
public typealias SignerFactory<P> = CryptographyOperationFactory<P, Signer>

public interface Signer : CryptographyOperation {
    public val signatureSize: Int
    public suspend fun sign(dataInput: Buffer): Buffer
    public suspend fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer
    public fun signBlocking(dataInput: Buffer): Buffer
    public fun signBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer
    public fun signFunction(): SignFunction
}
