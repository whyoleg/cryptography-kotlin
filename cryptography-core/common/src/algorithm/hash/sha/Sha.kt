package dev.whyoleg.cryptography.algorithm.hash.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithm.hash.*

public interface Sha : HashAlgorithm<Unit, Unit, Unit> {
    public companion object {
        public val SHA1: CryptographyAlgorithmIdentifier<Sha> = CryptographyAlgorithmIdentifier("SHA-1")
        public val SHA256: CryptographyAlgorithmIdentifier<Sha> = CryptographyAlgorithmIdentifier("SHA-256")
        public val SHA512: CryptographyAlgorithmIdentifier<Sha> = CryptographyAlgorithmIdentifier("SHA-512")
        public val SHA3_256: CryptographyAlgorithmIdentifier<Sha> = CryptographyAlgorithmIdentifier("SHA3-256")
        public val SHA3_512: CryptographyAlgorithmIdentifier<Sha> = CryptographyAlgorithmIdentifier("SHA3-512")
    }
}
