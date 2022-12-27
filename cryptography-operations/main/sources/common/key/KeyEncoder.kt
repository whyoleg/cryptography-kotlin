@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias KeyEncoderProvider<P, KF> = CryptographyOperationProvider<P, KeyEncoder<KF>>
public typealias KeyEncoderFactory<P, KF> = CryptographyOperationFactory<P, KeyEncoder<KF>>

public interface KeyEncoder<KF : KeyFormat> : CryptographyOperation {
    public suspend fun encodeTo(keyFormat: KF): Buffer
    public suspend fun encodeTo(keyFormat: KF, keyOutput: Buffer): Buffer
    public fun encodeToBlocking(keyFormat: KF): Buffer
    public fun encodeToBlocking(keyFormat: KF, keyOutput: Buffer): Buffer
}
