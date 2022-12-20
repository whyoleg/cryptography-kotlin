package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.mac.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.jdk.aes.*
import java.security.*

//TODO: add provider support
public class JdkCryptographyEngine(
    secureRandom: SecureRandom = SecureRandom(),
    provider: JdkProvider = JdkProvider.Default,
) : CryptographyEngine {
    private val state = JdkCryptographyState(provider, secureRandom)

    //TODO: use map?
    @Suppress("IMPLICIT_CAST_TO_ANY", "UNCHECKED_CAST")
    override fun <T> get(id: CryptographyAlgorithmIdentifier<T>): T = when (id) {
        AES.GCM -> AesGcm(state)
        AES.CBC -> AesCbc(state)
        SHA1    -> Sha(state, "SHA-1")
        SHA512  -> Sha(state, "SHA-512")
        HMAC    -> Hmac(state)
        else    -> throw CryptographyAlgorithmNotFoundException(id)
    } as T
}

private fun CryptographyEngineBuilder.test(state: JdkCryptographyState) {
    register(AES.CBC) {
        aesCbc(state)
    }
}
