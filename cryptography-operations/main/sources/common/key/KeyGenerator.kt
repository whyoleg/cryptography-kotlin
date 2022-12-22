package dev.whyoleg.cryptography.operations.key

import dev.whyoleg.cryptography.operations.*

public typealias KeyGeneratorFactory<P, K> = CryptographyOperationFactory<P, KeyGenerator<K>>
public typealias KeyGeneratorProvider<P, K> = CryptographyOperationProvider<P, KeyGenerator<K>>

public interface KeyGenerator<K> : CryptographyOperation {
    public suspend fun generateKey(): K
    public fun generateKeyBlocking(): K
}
