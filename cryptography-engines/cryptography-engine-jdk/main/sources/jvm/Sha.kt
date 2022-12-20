package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*

internal class Sha(
    state: JdkCryptographyState,
    algorithm: String,
) : HashAlgorithm() {
    private val hasher = JdkHasher(state, algorithm)
    override fun syncHasher(parameters: CryptographyParameters.Empty): SyncHasher = hasher

    override fun asyncHasher(parameters: CryptographyParameters.Empty): AsyncHasher {
        TODO("Not yet implemented")
    }

    override fun hashFunction(parameters: CryptographyParameters.Empty): HashFunction {
        TODO("Not yet implemented")
    }
}
