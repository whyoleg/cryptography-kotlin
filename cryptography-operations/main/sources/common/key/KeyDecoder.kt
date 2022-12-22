package dev.whyoleg.cryptography.operations.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias KeyDecoderFactory<P, K, KF> = CryptographyOperationFactory<P, KeyDecoder<K, KF>>
public typealias KeyDecoderProvider<P, K, KF> = CryptographyOperationProvider<P, KeyDecoder<K, KF>>

public interface KeyDecoder<K, KF : KeyFormat> : CryptographyOperation {
    public suspend fun decodeKey(format: KF, keyDataInput: Buffer): K
    public fun decodeKeyBlocking(format: KF, keyDataInput: Buffer): K
}
