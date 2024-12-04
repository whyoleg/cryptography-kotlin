/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.algorithms.*
import dev.whyoleg.cryptography.random.*
import java.security.*
import java.util.concurrent.*

private val defaultProvider = lazy { CryptographyProvider.Companion.JDK() }

public val CryptographyProvider.Companion.JDK: CryptographyProvider by defaultProvider

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
): CryptographyProvider = JDK(cryptographyRandom.asSecureRandom())

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    provider: Provider,
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
): CryptographyProvider = JDK(provider, cryptographyRandom.asSecureRandom())

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    providerName: String,
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
): CryptographyProvider = JDK(providerName, cryptographyRandom.asSecureRandom())

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    secureRandom: SecureRandom,
): CryptographyProvider = JdkCryptographyProvider(null, secureRandom)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    provider: Provider,
    secureRandom: SecureRandom,
): CryptographyProvider = JdkCryptographyProvider(provider, secureRandom)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    providerName: String,
    secureRandom: SecureRandom,
): CryptographyProvider {
    val provider = checkNotNull(Security.getProvider(providerName)) { "No provider with name: $providerName" }
    return JdkCryptographyProvider(provider, secureRandom)
}

internal class JdkCryptographyProvider(
    provider: Provider?,
    secureRandom: SecureRandom,
) : CryptographyProvider() {
    private val state = JdkCryptographyState(provider, secureRandom)
    override val name: String = when (provider) {
        null -> "JDK"
        else -> "JDK (${provider.name})"
    }

    private val cache = ConcurrentHashMap<CryptographyAlgorithmId<*>, CryptographyAlgorithm?>()

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = cache.getOrPut(identifier) {
        when (identifier) {
            MD5       -> JdkDigest(state, "MD5", MD5)
            SHA1      -> JdkDigest(state, "SHA-1", SHA1)
            SHA224    -> JdkDigest(state, "SHA-224", SHA224)
            SHA256    -> JdkDigest(state, "SHA-256", SHA256)
            SHA384    -> JdkDigest(state, "SHA-384", SHA384)
            SHA512    -> JdkDigest(state, "SHA-512", SHA512)
            SHA3_224  -> JdkDigest(state, "SHA3-224", SHA3_224)
            SHA3_256  -> JdkDigest(state, "SHA3-256", SHA3_256)
            SHA3_384  -> JdkDigest(state, "SHA3-384", SHA3_384)
            SHA3_512  -> JdkDigest(state, "SHA3-512", SHA3_512)
            RIPEMD128 -> JdkDigest(state, "RIPEMD128", RIPEMD128)
            RIPEMD160 -> JdkDigest(state, "RIPEMD160", RIPEMD160)
            RIPEMD256 -> JdkDigest(state, "RIPEMD256", RIPEMD256)
            RIPEMD320 -> JdkDigest(state, "RIPEMD320", RIPEMD320)
            HMAC     -> JdkHmac(state)
            AES.CBC  -> JdkAesCbc(state)
            AES.CTR  -> JdkAesCtr(state)
            AES.ECB  -> JdkAesEcb(state)
            AES.GCM  -> JdkAesGcm(state)
            RSA.OAEP -> JdkRsaOaep(state)
            RSA.PSS   -> JdkRsaPss(state)
            RSA.PKCS1 -> JdkRsaPkcs1(state)
            RSA.RAW  -> JdkRsaRaw(state)
            ECDSA     -> JdkEcdsa(state)
            ECDH   -> JdkEcdh(state)
            PBKDF2 -> JdkPbkdf2(state)
            HKDF   -> JdkHkdf(state, this)
            else      -> null
        }
    } as A?
}

internal class JdkCryptographyProviderContainer : CryptographyProviderContainer {
    override val provider: Lazy<CryptographyProvider> get() = defaultProvider
}
