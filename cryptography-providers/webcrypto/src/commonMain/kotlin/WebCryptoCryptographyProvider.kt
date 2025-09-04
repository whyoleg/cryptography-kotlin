/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.webcrypto.algorithms.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.Engine
import dev.whyoleg.cryptography.providers.webcrypto.internal.detectEngine

internal val defaultProvider = lazy { WebCryptoCryptographyProvider }

public val CryptographyProvider.Companion.WebCrypto: CryptographyProvider by defaultProvider

internal object WebCryptoCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "WebCrypto"

    private val engine: Engine = detectEngine()
    private var experimentalEdwardsEnabled: Boolean = false

    internal fun setExperimentalEdwards(value: Boolean) {
        experimentalEdwardsEnabled = value
    }

    private fun supportsEdwards(): Boolean = when (engine) {
        Engine.Node, Engine.Firefox, Engine.Safari -> true
        Engine.Chromium, Engine.Unknown            -> experimentalEdwardsEnabled
    }

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        SHA1      -> WebCryptoDigest.sha1
        SHA256    -> WebCryptoDigest.sha256
        SHA384    -> WebCryptoDigest.sha384
        SHA512    -> WebCryptoDigest.sha512
        HMAC     -> WebCryptoHmac
        AES.CBC  -> WebCryptoAesCbc
        AES.CTR  -> WebCryptoAesCtr
        AES.GCM  -> WebCryptoAesGcm
        RSA.OAEP -> WebCryptoRsaOaep
        RSA.PSS   -> WebCryptoRsaPss
        RSA.PKCS1 -> WebCryptoRsaPkcs1
        ECDSA     -> WebCryptoEcdsa
        EdDSA     -> if (supportsEdwards()) WebCryptoEdDSA else null
        ECDH   -> WebCryptoEcdh
        XDH       -> if (supportsEdwards()) WebCryptoXDH else null
        PBKDF2 -> WebCryptoPbkdf2
        HKDF   -> WebCryptoHkdf
        else      -> null
    } as A?
}

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.WebCrypto(
    enableExperimentalEdwards: Boolean,
): CryptographyProvider {
    WebCryptoCryptographyProvider.setExperimentalEdwards(enableExperimentalEdwards)
    return WebCryptoCryptographyProvider
}
