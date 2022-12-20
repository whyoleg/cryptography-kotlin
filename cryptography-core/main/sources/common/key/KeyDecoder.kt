package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public typealias KeyDecoderFactory<P, K> = CryptographyOperationFactory<P, KeyDecoder<K>>
public typealias KeyDecoderProvider<P, K> = CryptographyOperationProvider<P, KeyDecoder<K>>

public interface KeyDecoder<K> : CryptographyOperation {
    public suspend fun decodeKey(format: String, keyDataInput: Buffer): K
    public fun decodeKeyBlocking(format: String, keyDataInput: Buffer): K
}
