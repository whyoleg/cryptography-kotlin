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
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        PlatformDependantRandom -> WebCryptoRandom
        SHA1                    -> WebCryptoDigest.SHA1
        SHA256                  -> WebCryptoDigest.SHA256
        SHA384                  -> WebCryptoDigest.SHA384
        SHA512                  -> WebCryptoDigest.SHA512
        HMAC                    -> WebCryptoHmac
        AES.CBC                 -> WebCryptoAesCbc
        AES.GCM                 -> WebCryptoAesGcm
        RSA.OAEP                -> WebCryptoRsaOaep
        RSA.PSS                 -> WebCryptoRsaPss
        else                    -> null
    } as A?
}
