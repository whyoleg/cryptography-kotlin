package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.jdk.aes.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*
import java.security.*

public val CryptographyProvider.Companion.JDK: CryptographyProvider by lazy(CryptographyProvider.Companion::JDK)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    secureRandom: SecureRandom = SecureRandom(),
    provider: JdkProvider = JdkProvider.Default,
    adaptor: SuspendAdaptor? = null,
): CryptographyProvider = JdkCryptographyProvider(JdkCryptographyState(provider, secureRandom, adaptor))

internal class JdkCryptographyProvider(
    private val state: JdkCryptographyState,
) : CryptographyProvider("JDK") {

    private val cache = mutableMapOf<CryptographyAlgorithmIdentifier<*>, CryptographyAlgorithm>()

    private inline fun <A : CryptographyAlgorithm, X : CryptographyAlgorithm> CryptographyAlgorithmIdentifier<A>.registerIf(
        identifier: CryptographyAlgorithmIdentifier<X>,
        return2: (X) -> Nothing,
        block: () -> X,
    ) {
        if (this !== identifier) return
        val algorithm = block()
        cache[identifier] = algorithm
        return2(algorithm)
    }

    //TODO: use map?
    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A {
        return when (identifier) {
            AES.GCM -> AES.GCM(
                AesGcmKeyGeneratorProvider(state),
                NotSupportedProvider()
            )
            AES.CBC -> AES.CBC(
                AesCbcKeyGeneratorProvider(state),
                NotSupportedProvider()
            )
            SHA1    -> SHA(JdkHasherProvider(state, "SHA-1"))
            SHA512  -> SHA(JdkHasherProvider(state, "SHA-512"))
            HMAC    -> HMAC(
                HmacKeyGeneratorProvider(state),
                NotSupportedProvider()
            )
            else    -> throw CryptographyAlgorithmNotFoundException(identifier)
        } as A
    }

}

//private fun CryptographyEngineBuilder.test(state: JdkCryptographyState) {
//    register(AES.CBC) {
//        aesCbc(state)
//    }
//}
