package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.hash.*
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

    override suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        return hash(dataInput).copyInto(digestOutput)
    }

    override fun hashBlocking(dataInput: Buffer): Buffer = nonBlocking()
    override fun hashBlocking(dataInput: Buffer, digestOutput: Buffer): Buffer = nonBlocking()
}

internal fun CryptographyAlgorithmId<Digest>.hashAlgorithmName(): String = when (this) {
    SHA1   -> "SHA-1"
    SHA256 -> "SHA-256"
    SHA384 -> "SHA-384"
    SHA512 -> "SHA-512"
    else   -> throw CryptographyException("Unsupported hash algorithm: ${this}")
}

internal fun hashAlgorithmDigestSize(algorithm: String): Int = when (algorithm) {
    "SHA-1"   -> 20
    "SHA-256" -> 32
    "SHA-384" -> 48
    "SHA-512" -> 64
    else      -> throw CryptographyException("Unsupported hash algorithm: $algorithm")
}
