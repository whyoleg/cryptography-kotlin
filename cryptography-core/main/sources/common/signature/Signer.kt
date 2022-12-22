package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.io.*

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
