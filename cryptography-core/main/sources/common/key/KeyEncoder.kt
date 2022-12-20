package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public typealias KeyEncoderFactory<P> = CryptographyOperationFactory<P, KeyEncoder>
public typealias KeyEncoderProvider<P> = CryptographyOperationProvider<P, KeyEncoder>

public interface KeyEncoder : CryptographyOperation {
    public suspend fun encodeKey(format: String): Buffer
    public suspend fun encodeKey(format: String, keyDataOutput: Buffer): Buffer
    public fun encodeKeyBlocking(format: String): Buffer
    public fun encodeKeyBlocking(format: String, keyDataOutput: Buffer): Buffer
}
