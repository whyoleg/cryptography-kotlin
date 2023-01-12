package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SHAKE : CryptographyAlgorithm {
    public fun hasher(digestSize: BinarySize): Hasher

    public object B128 : CryptographyAlgorithmId<SHAKE>()
    public object B256 : CryptographyAlgorithmId<SHAKE>()
}

private fun test(engine: CryptographyProvider) {
    engine.get(SHA256)

    val shake = engine.get(SHAKE.B128)

    val hasher = shake.hasher(256.bytes)

    hasher.hashBlocking(ByteArray(10))
}
