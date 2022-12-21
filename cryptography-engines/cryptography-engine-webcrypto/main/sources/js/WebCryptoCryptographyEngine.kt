package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.mac.*
import dev.whyoleg.cryptography.algorithms.sha.*

internal val ENGINE_ID get() = CryptographyEngineId("WebCrypto")

public object WebCryptoCryptographyEngine : CryptographyEngine(ENGINE_ID) {

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A = when (identifier) {
        AES.GCM -> AES.GCM(
            AesGcmKeyGeneratorProvider,
            NotSupportedProvider(ENGINE_ID)
        )
        AES.CBC -> AES.CBC(
            AesCbcKeyGeneratorProvider,
            NotSupportedProvider(ENGINE_ID)
        )
        SHA1    -> SHA(WebCryptoHasherProvider("SHA-1"))
        SHA512  -> SHA(WebCryptoHasherProvider("SHA-512"))
        HMAC    -> HMAC(
            HmacKeyGeneratorProvider,
            NotSupportedProvider(ENGINE_ID)
        )
        else    -> throw CryptographyAlgorithmNotFoundException(identifier)
    } as A
}
