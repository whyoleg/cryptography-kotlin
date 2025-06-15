/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.algorithms.*
import dev.whyoleg.cryptography.random.*
import java.security.*
import java.util.*
import java.util.concurrent.*

private val defaultProvider = lazy {
    val defaultSecurityProviders = loadViaServiceLoader().toList()
    if (defaultSecurityProviders.size > 1) {
        error("Multiple default JDK security providers found: $defaultSecurityProviders")
    }
    JdkCryptographyProvider(defaultSecurityProviders.singleOrNull()?.provider?.value)
}

// uses default security provider registered
public val CryptographyProvider.Companion.JDK: CryptographyProvider by defaultProvider

// uses all providers registered in the system
@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(): CryptographyProvider = JdkCryptographyProvider(null)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(provider: Provider): CryptographyProvider = JdkCryptographyProvider(provider)

@Deprecated(
    message = "Secure random should be provided via CryptographySystem.setDefaultRandom",
    level = DeprecationLevel.ERROR,
    replaceWith = ReplaceWith("CryptographyProvider.JDK")
)
@Suppress("FunctionName", "DEPRECATION_ERROR")
public fun CryptographyProvider.Companion.JDK(
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
): CryptographyProvider = JDK(cryptographyRandom.asSecureRandom())

@Deprecated(
    message = "Secure random should be provided via CryptographySystem.setDefaultRandom",
    level = DeprecationLevel.ERROR,
    replaceWith = ReplaceWith("CryptographyProvider.JDK(provider)")
)
@Suppress("FunctionName", "DEPRECATION_ERROR")
public fun CryptographyProvider.Companion.JDK(
    provider: Provider,
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
): CryptographyProvider = JDK(provider, cryptographyRandom.asSecureRandom())

@Deprecated(
    message = "Overload with `provideName` is deprecated, use Security.getProvider(providerName) instead",
    level = DeprecationLevel.ERROR,
    replaceWith = ReplaceWith("CryptographyProvider.JDK(checkNotNull(Security.getProvider(providerName)))")
)
@Suppress("FunctionName", "DEPRECATION_ERROR")
public fun CryptographyProvider.Companion.JDK(
    providerName: String,
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
): CryptographyProvider = JDK(providerName, cryptographyRandom.asSecureRandom())

@Deprecated(
    message = "Secure random should be provided via CryptographySystem.setDefaultRandom",
    level = DeprecationLevel.ERROR,
    replaceWith = ReplaceWith("CryptographyProvider.JDK(provider)")
)
@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    secureRandom: SecureRandom,
): CryptographyProvider = JdkCryptographyProvider(null)

@Deprecated(
    message = "Secure random should be provided via CryptographySystem.setDefaultRandom",
    level = DeprecationLevel.ERROR,
    replaceWith = ReplaceWith("CryptographyProvider.JDK(provider)")
)
@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    provider: Provider,
    secureRandom: SecureRandom,
): CryptographyProvider = JdkCryptographyProvider(provider)

@Deprecated(
    message = "Overload with `provideName` is deprecated, use Security.getProvider(providerName) instead",
    level = DeprecationLevel.ERROR,
    replaceWith = ReplaceWith("CryptographyProvider.JDK(checkNotNull(Security.getProvider(providerName)))")
)
@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    providerName: String,
    secureRandom: SecureRandom,
): CryptographyProvider {
    val provider = checkNotNull(Security.getProvider(providerName)) { "No provider with name: $providerName" }
    return JdkCryptographyProvider(provider)
}

internal class JdkCryptographyProvider(provider: Provider?) : CryptographyProvider() {
    private val state = JdkCryptographyState(provider)
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
            RIPEMD160 -> JdkDigest(state, "RIPEMD160", RIPEMD160)
            HMAC      -> JdkHmac(state)
            AES.CBC   -> JdkAesCbc(state)
            AES.CMAC  -> JdkAesCmac(state)
            AES.CTR   -> JdkAesCtr(state)
            AES.ECB   -> JdkAesEcb(state)
            AES.GCM   -> JdkAesGcm(state)
            RSA.OAEP  -> JdkRsaOaep(state)
            RSA.PSS   -> JdkRsaPss(state)
            RSA.PKCS1 -> JdkRsaPkcs1(state)
            RSA.RAW   -> JdkRsaRaw(state)
            ECDSA     -> JdkEcdsa(state)
            ECDH      -> JdkEcdh(state)
            PBKDF2    -> JdkPbkdf2(state)
            HKDF      -> JdkHkdf(state, this)
            else      -> null
        }
    } as A?
}

internal class JdkCryptographyProviderContainer : CryptographyProviderContainer {
    override val priority: Int get() = 100
    override val provider: Lazy<CryptographyProvider> get() = defaultProvider
}

@CryptographyProviderApi
public interface DefaultJdkSecurityProvider {
    public val provider: Lazy<JProvider>
}

// uses specific calling convention to be optimized by R8
@OptIn(CryptographyProviderApi::class)
private fun loadViaServiceLoader(): Iterable<DefaultJdkSecurityProvider> = Iterable {
    ServiceLoader.load(
        DefaultJdkSecurityProvider::class.java,
        DefaultJdkSecurityProvider::class.java.classLoader
    ).iterator()
}
