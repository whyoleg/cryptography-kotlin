package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.mac.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
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

internal object Hmac : HMAC {
    override fun syncKeyGenerator(parameters: HMAC.KeyGeneratorParameters): SyncKeyGenerator<HMAC.Key> {
        TODO("Not yet implemented")
    }

    override fun asyncKeyGenerator(parameters: HMAC.KeyGeneratorParameters): AsyncKeyGenerator<HMAC.Key> {
        val hashAlgorithm = when (parameters.algorithm.algorithm) {
            SHA1   -> "SHA-1"
            SHA512 -> "SHA-512"
            else   -> throw CryptographyException("Unsupported hash algorithm: ${parameters.algorithm.algorithm}")
        }
        return HmacKeyGenerator(hashAlgorithm)
    }
}

internal class HmacKeyGenerator(
    private val hashAlgorithm: String,
) : AsyncKeyGenerator<HMAC.Key> {
    override suspend fun generateKey(): HMAC.Key {
        val key = WebCrypto.subtle.generateKey(
            Algorithm<HmacKeyGenerationAlgorithm>(name = "HMAC") {
                this.hash = hashAlgorithm
            },
            true,
            arrayOf("sign", "verify"),
        ).await()
        return HmacKey(key)
    }
}

internal class HmacKey(
    private val key: CryptoKey,
) : HMAC.Key {
    override fun syncSignature(parameters: CryptographyParameters.Empty): SyncSignature {
        TODO("Not yet implemented")
    }

    override fun asyncSignature(parameters: CryptographyParameters.Empty): AsyncSignature {
        return WebCryptoHmacSignature(key)
    }

    override fun signFunction(parameters: CryptographyParameters.Empty): SignFunction {
        TODO("Not yet implemented")
    }

    override fun verifyFunction(parameters: CryptographyParameters.Empty): VerifyFunction {
        TODO("Not yet implemented")
    }
}

internal class WebCryptoHmacSignature(
    private val key: CryptoKey,
) : AsyncSignature {
    override val signatureSize: Int
        get() = TODO("Not yet implemented")

    override suspend fun sign(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.sign(Algorithm("HMAC"), key, dataInput).await()
    }

    override suspend fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        return sign(dataInput).copyInto(signatureOutput)
    }

    override suspend fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return WebCrypto.subtle.verify(Algorithm("HMAC"), key, signatureInput, dataInput).await()
    }
}
