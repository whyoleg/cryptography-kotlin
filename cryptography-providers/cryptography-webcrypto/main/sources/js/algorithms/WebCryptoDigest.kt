package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoDigest private constructor(
    private val algorithm: String,
) : Digest, Hasher {
    //TODO: lazy?
    companion object {
        val SHA1 = WebCryptoDigest("SHA-1")
        val SHA256 = WebCryptoDigest("SHA-256")
        val SHA384 = WebCryptoDigest("SHA-384")
        val SHA512 = WebCryptoDigest("SHA-512")
    }

    override fun hasher(): Hasher = this

    override val digestSize: Int = hashAlgorithmDigestSize(algorithm)

    override suspend fun hash(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.digest(algorithm, dataInput).await().toByteArray()
    }

    override fun hashBlocking(dataInput: Buffer): Buffer = nonBlocking()
}
