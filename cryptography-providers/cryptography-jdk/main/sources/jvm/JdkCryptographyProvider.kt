package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.algorithms.*
import dev.whyoleg.cryptography.jdk.operations.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import java.security.*
import java.util.concurrent.*

private val defaultProvider = lazy { CryptographyProvider.Companion.JDK() }

public val CryptographyProvider.Companion.JDK: CryptographyProvider by defaultProvider

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    provider: JdkProvider = JdkProvider.Default,
    cryptographyRandom: CryptographyRandom = CryptographyRandom.Default,
    adaptor: SuspendAdaptor? = null,
): CryptographyProvider = JdkCryptographyProvider(JdkCryptographyState(provider, cryptographyRandom.asSecureRandom(), adaptor))

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    provider: JdkProvider = JdkProvider.Default,
    secureRandom: SecureRandom,
    adaptor: SuspendAdaptor? = null,
): CryptographyProvider = JdkCryptographyProvider(JdkCryptographyState(provider, secureRandom, adaptor))

internal class JdkCryptographyProvider(
    private val state: JdkCryptographyState,
) : CryptographyProvider() {
    override val name: String get() = "JDK"

    private val cache = ConcurrentHashMap<CryptographyAlgorithmId<*>, CryptographyAlgorithm?>()

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = cache.getOrPut(identifier) {
        when (identifier) {
            MD5      -> JdkDigest(state, "MD5")
            SHA1     -> JdkDigest(state, "SHA-1")
            SHA256   -> JdkDigest(state, "SHA-256")
            SHA384   -> JdkDigest(state, "SHA-384")
            SHA512   -> JdkDigest(state, "SHA-512")
            HMAC     -> JdkHmac(state)
            AES.CBC  -> JdkAesCbc(state)
            AES.GCM  -> JdkAesGcm(state)
            RSA.OAEP -> JdkRsaOaep(state)
            RSA.PSS  -> JdkRsaPss(state)
            ECDSA    -> JdkEcdsa(state)
            else     -> null
        }
    } as A?
}

@Suppress("DEPRECATION_ERROR")
internal class JdkCryptographyProviderContainer : CryptographyProviderContainer {
    override val provider: Lazy<CryptographyProvider> get() = defaultProvider
}
