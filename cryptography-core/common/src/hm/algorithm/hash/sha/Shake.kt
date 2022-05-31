package dev.whyoleg.cryptography.hm.algorithm.hash.sha

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.cryptography.hm.algorithm.hash.*
import dev.whyoleg.vio.*
import kotlin.jvm.*

public interface Shake : HashAlgorithm<Shake.DigestSize> {
    @JvmInline
    public value class DigestSize(public val size: BinarySize)

    public companion object {
        public val SHAKE128: CryptographyAlgorithmIdentifier<Shake> = CryptographyAlgorithmIdentifier("SHAKE128")
        public val SHAKE256: CryptographyAlgorithmIdentifier<Shake> = CryptographyAlgorithmIdentifier("SHAKE256")
    }
}
