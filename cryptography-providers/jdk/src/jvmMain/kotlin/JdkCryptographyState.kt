/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import java.util.concurrent.*

//candidate for context parameters
internal class JdkCryptographyState(private val provider: JProvider?) {
    // TODO: move to something global?
    val secureRandom: JSecureRandom = CryptographySystem.getDefaultRandom().asSecureRandom()

    private val ciphers: ConcurrentHashMap<String, Pooled<JCipher>> = ConcurrentHashMap()
    private val messageDigests: ConcurrentHashMap<String, Pooled<JMessageDigest>> = ConcurrentHashMap()
    private val macs: ConcurrentHashMap<String, Pooled<JMac>> = ConcurrentHashMap()
    private val signatures: ConcurrentHashMap<String, Pooled<JSignature>> = ConcurrentHashMap()
    private val keyGenerators: ConcurrentHashMap<String, Pooled<JKeyGenerator>> = ConcurrentHashMap()
    private val keyPairGenerators: ConcurrentHashMap<String, Pooled<JKeyPairGenerator>> = ConcurrentHashMap()
    private val keyFactories: ConcurrentHashMap<String, Pooled<JKeyFactory>> = ConcurrentHashMap()
    private val secretKeyFactories: ConcurrentHashMap<String, Pooled<JSecretKeyFactory>> = ConcurrentHashMap()
    private val algorithmParameters: ConcurrentHashMap<String, Pooled<JAlgorithmParameters>> = ConcurrentHashMap()
    private val algorithmParameterGenerators: ConcurrentHashMap<String, Pooled<JAlgorithmParameterGenerator>> = ConcurrentHashMap()
    private val keyAgreements: ConcurrentHashMap<String, Pooled<JKeyAgreement>> = ConcurrentHashMap()

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

    fun cipher(algorithm: String, cached: Boolean = true): Pooled<JCipher> =
        ciphers.get(algorithm, JCipher::getInstance, JCipher::getInstance, cached)

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

    fun secretKeyFactory(algorithm: String): Pooled<JSecretKeyFactory> =
        secretKeyFactories.get(algorithm, JSecretKeyFactory::getInstance, JSecretKeyFactory::getInstance)

    fun algorithmParameters(algorithm: String): JAlgorithmParameters =
        algorithmParameters.get(algorithm, JAlgorithmParameters::getInstance, JAlgorithmParameters::getInstance, cached = false).use { it }

    fun algorithmParameterGenerator(algorithm: String): Pooled<JAlgorithmParameterGenerator> =
        algorithmParameterGenerators.get(algorithm, JAlgorithmParameterGenerator::getInstance, JAlgorithmParameterGenerator::getInstance)

    fun keyAgreement(algorithm: String): Pooled<JKeyAgreement> =
        keyAgreements.get(algorithm, JKeyAgreement::getInstance, JKeyAgreement::getInstance)

}

internal fun CryptographyAlgorithmId<Digest>?.hashECAlgorithmName(): String = when (this) {
    null     -> "NONE"
    else -> hashAlgorithmName()
}

internal fun CryptographyAlgorithmId<Digest>.hashAlgorithmName(): String = when (this) {
    SHA1     -> "SHA1"
    SHA224   -> "SHA224"
    SHA256   -> "SHA256"
    SHA384   -> "SHA384"
    SHA512   -> "SHA512"
    SHA3_224 -> "SHA3-224"
    SHA3_256 -> "SHA3-256"
    SHA3_384 -> "SHA3-384"
    SHA3_512 -> "SHA3-512"
    else -> throw IllegalStateException("Unsupported hash algorithm: $this")
}
