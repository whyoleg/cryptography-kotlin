@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias HasherProvider<P> = CryptographyOperationProvider<P, Hasher>
public typealias HasherFactory<P> = CryptographyOperationFactory<P, Hasher>

public interface Hasher : CryptographyOperation {
    public val digestSize: Int
    public suspend fun hash(dataInput: Buffer): Buffer
    public suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
    public fun hashBlocking(dataInput: Buffer): Buffer
    public fun hashBlocking(dataInput: Buffer, digestOutput: Buffer): Buffer
}
