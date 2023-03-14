/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.algorithms.*

public val CryptographyProvider.Companion.WebCrypto: CryptographyProvider get() = WebCryptoCryptographyProvider

internal object WebCryptoCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "WebCrypto"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        SHA1     -> WebCryptoDigest.sha1
        SHA256   -> WebCryptoDigest.sha256
        SHA384   -> WebCryptoDigest.sha384
        SHA512   -> WebCryptoDigest.sha512
        HMAC     -> WebCryptoHmac
        AES.CBC  -> WebCryptoAesCbc
        AES.GCM  -> WebCryptoAesGcm
        RSA.OAEP -> WebCryptoRsaOaep
        RSA.PSS  -> WebCryptoRsaPss
        ECDSA    -> WebCryptoEcdsa
        else     -> null
    } as A?
}

@Suppress("DEPRECATION", "INVISIBLE_MEMBER")
@OptIn(ExperimentalStdlibApi::class, ExperimentalJsExport::class)
@EagerInitialization
@JsExport
@Deprecated("", level = DeprecationLevel.HIDDEN)
public val initHook: dynamic = registerProvider { WebCryptoCryptographyProvider }
