package dev.whyoleg.cryptography.algorithm.hash.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithm.hash.*
import dev.whyoleg.vio.*
import kotlin.jvm.*

public interface Shake : HashAlgorithm<Unit, Shake.DigestSize, Shake.DigestSize> {
    @JvmInline
    public value class DigestSize(public val size: BinarySize)

    public companion object {
        public val SHAKE128: CryptographyAlgorithmIdentifier<Shake> = CryptographyAlgorithmIdentifier("SHAKE128")
        public val SHAKE256: CryptographyAlgorithmIdentifier<Shake> = CryptographyAlgorithmIdentifier("SHAKE256")
    }
}
