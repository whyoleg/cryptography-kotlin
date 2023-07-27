/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import java.util.concurrent.*

//candidate for context receivers
internal class JdkCryptographyState(
    private val provider: JProvider?,
    val secureRandom: JSecureRandom,
) {

    private val ciphers: ConcurrentHashMap<String, Pooled<JCipher>> = ConcurrentHashMap()
    private val messageDigests: ConcurrentHashMap<String, Pooled<JMessageDigest>> = ConcurrentHashMap()
    private val macs: ConcurrentHashMap<String, Pooled<JMac>> = ConcurrentHashMap()
    private val signatures: ConcurrentHashMap<String, Pooled<JSignature>> = ConcurrentHashMap()
    private val keyGenerators: ConcurrentHashMap<String, Pooled<JKeyGenerator>> = ConcurrentHashMap()
    private val keyPairGenerators: ConcurrentHashMap<String, Pooled<JKeyPairGenerator>> = ConcurrentHashMap()
    private val keyFactories: ConcurrentHashMap<String, Pooled<JKeyFactory>> = ConcurrentHashMap()
    private val algorithmParameters: ConcurrentHashMap<String, Pooled<JAlgorithmParameters>> = ConcurrentHashMap()

    private inline fun <T> ConcurrentHashMap<String, Pooled<T>>.get(
        algorithm: String,
        crossinline fromDefault: (String) -> T,
        crossinline fromProvider: (String, JProvider) -> T,
        cached: Boolean = true,
    ): Pooled<T> = getOrPut(algorithm) {
        val instantiate = when (val provider = provider) {
            null -> {
                { fromDefault(algorithm) }
            }
            else -> {
                { fromProvider(algorithm, provider) }
            }
        }
        when (cached) {
            true  -> Pooled.Cached(instantiate)
            false -> Pooled.Empty(instantiate)
        }
    }

    fun cipher(algorithm: String): Pooled<JCipher> =
        ciphers.get(algorithm, JCipher::getInstance, JCipher::getInstance)

    fun messageDigest(algorithm: String): Pooled<JMessageDigest> =
        messageDigests.get(algorithm, JMessageDigest::getInstance, JMessageDigest::getInstance)

    fun mac(algorithm: String): Pooled<JMac> =
        macs.get(algorithm, JMac::getInstance, JMac::getInstance)

    fun signature(algorithm: String): Pooled<JSignature> =
        signatures.get(algorithm, JSignature::getInstance, JSignature::getInstance, cached = false)

    fun keyGenerator(algorithm: String): Pooled<JKeyGenerator> =
        keyGenerators.get(algorithm, JKeyGenerator::getInstance, JKeyGenerator::getInstance)

    fun keyPairGenerator(algorithm: String): Pooled<JKeyPairGenerator> =
        keyPairGenerators.get(algorithm, JKeyPairGenerator::getInstance, JKeyPairGenerator::getInstance)

    fun keyFactory(algorithm: String): Pooled<JKeyFactory> =
        keyFactories.get(algorithm, JKeyFactory::getInstance, JKeyFactory::getInstance)

    fun algorithmParameters(algorithm: String): Pooled<JAlgorithmParameters> =
        algorithmParameters.get(algorithm, JAlgorithmParameters::getInstance, JAlgorithmParameters::getInstance, cached = false)
}

internal fun CryptographyAlgorithmId<Digest>.hashAlgorithmName(): String = when (this) {
    SHA1   -> "SHA1"
    SHA256 -> "SHA256"
    SHA384 -> "SHA384"
    SHA512 -> "SHA512"
    else   -> throw CryptographyException("Unsupported hash algorithm: $this")
}
