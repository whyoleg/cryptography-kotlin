package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*

internal object WebCryptoCryptographyEngine : CryptographyProvider("WebCrypto") {

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A = when (identifier) {
        AES.GCM                 -> AES.GCM(
            AesGcmKeyGeneratorProvider,
            NotSupportedProvider()
        )
        AES.CBC                 -> AES.CBC(
            AesCbcKeyGeneratorProvider,
            NotSupportedProvider()
        )
        SHA1                    -> SHA(WebCryptoHasherProvider("SHA-1"))
        SHA512                  -> SHA(WebCryptoHasherProvider("SHA-512"))
        HMAC                    -> HMAC(
            HmacKeyGeneratorProvider,
            NotSupportedProvider()
        )
        PlatformDependantRandom -> PlatformDependantRandom(
            WebCryptoRandom
        )
        else                    -> throw CryptographyAlgorithmNotFoundException(identifier)
    } as A
}
