@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias KeyDecoderProvider<P, K, KF> = CryptographyOperationProvider<P, KeyDecoder<K, KF>>
public typealias KeyDecoderFactory<P, K, KF> = CryptographyOperationFactory<P, KeyDecoder<K, KF>>

public interface KeyDecoder<K, KF : KeyFormat> : CryptographyOperation {
    public suspend fun decodeFrom(keyFormat: KF, keyInput: Buffer): K
    public fun decodeFromBlocking(keyFormat: KF, keyInput: Buffer): K
}
