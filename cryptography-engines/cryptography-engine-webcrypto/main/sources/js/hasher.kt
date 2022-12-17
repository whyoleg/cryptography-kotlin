package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class Sha(algorithm: String) : SHA() {
    private val hasher = WebCryptoHasher(algorithm)
    override fun syncHasher(parameters: CryptographyParameters.Empty): SyncHasher {
        TODO("Not yet implemented")
    }

    override fun asyncHasher(parameters: CryptographyParameters.Empty): AsyncHasher = hasher

    override fun hashFunction(parameters: CryptographyParameters.Empty): HashFunction {
        TODO("Not yet implemented")
    }
}

internal class WebCryptoHasher(
    private val algorithm: String,
) : AsyncHasher {
    override val digestSize: Int
        get() = TODO("Not yet implemented")

    override suspend fun hash(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.digest(algorithm, dataInput).await().toByteArray()
    }

    override suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        return hash(dataInput).copyInto(digestOutput)
    }
}
