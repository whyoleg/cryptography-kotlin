/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.webcrypto.algorithms.*

internal val defaultProvider = lazy { WebCryptoCryptographyProvider }

public val CryptographyProvider.Companion.WebCrypto: CryptographyProvider by defaultProvider

internal object WebCryptoCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "WebCrypto"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        SHA1      -> WebCryptoDigest.sha1
        SHA256    -> WebCryptoDigest.sha256
        SHA384    -> WebCryptoDigest.sha384
        SHA512    -> WebCryptoDigest.sha512
        HMAC      -> WebCryptoHmac
        AES.CBC   -> WebCryptoAesCbc
        AES.CTR -> WebCryptoAesCtr
        AES.GCM   -> WebCryptoAesGcm
        RSA.OAEP  -> WebCryptoRsaOaep
        RSA.PSS   -> WebCryptoRsaPss
        RSA.PKCS1 -> WebCryptoRsaPkcs1
        ECDSA     -> WebCryptoEcdsa
        else      -> null
    } as A?
}
