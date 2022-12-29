package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*

internal object WebCryptoCryptographyEngine : CryptographyProvider("WebCrypto") {

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A = when (identifier) {
        SHA1                    -> WebCryptoHasher.SHA1
        SHA256                  -> WebCryptoHasher.SHA256
        SHA384                  -> WebCryptoHasher.SHA384
        SHA512                  -> WebCryptoHasher.SHA512
        PlatformDependantRandom -> PlatformDependantRandom(WebCryptoRandom)
        AES.GCM                 -> AES.GCM(
            AesGcmKeyGeneratorProvider,
            NotSupportedProvider()
        )
        AES.CBC                 -> AES.CBC(
            AesCbcKeyGeneratorProvider,
            NotSupportedProvider()
        )

        HMAC                    -> HMAC(
            HmacKeyGeneratorProvider,
            NotSupportedProvider()
        )
        RSA.OAEP                -> RSA.OAEP(
            RsaOaepKeyGeneratorProvider
        )
        RSA.PSS                 -> RSA.PSS(
            RsaPssKeyGeneratorProvider
        )
        else                    -> throw CryptographyAlgorithmNotFoundException(identifier)
    } as A
}
