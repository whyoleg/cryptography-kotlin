package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.mac.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.engine.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*

internal val ENGINE_ID get() = CryptographyProviderId("WebCrypto")

public val CryptographyProvider.Companion.WebCrypto: CryptographyProvider get() = WebCryptoCryptographyEngine

internal object WebCryptoCryptographyEngine : CryptographyProvider(ENGINE_ID) {

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
