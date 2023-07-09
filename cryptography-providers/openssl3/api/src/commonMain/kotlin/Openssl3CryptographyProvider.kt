/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.openssl3.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.provider.*
import kotlinx.cinterop.*

private val defaultProvider = lazy { Openssl3CryptographyProvider }

public val CryptographyProvider.Companion.Openssl3: CryptographyProvider by defaultProvider

internal object Openssl3CryptographyProvider : CryptographyProvider() {
    override val name: String = "OpenSSL3 (${OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString() ?: "unknown"})"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        MD5       -> Openssl3Digest("MD5", MD5)
        SHA1      -> Openssl3Digest("SHA1", SHA1)
        SHA256    -> Openssl3Digest("SHA256", SHA256)
        SHA384    -> Openssl3Digest("SHA384", SHA384)
        SHA512    -> Openssl3Digest("SHA512", SHA512)
        HMAC      -> Openssl3Hmac
        AES.CBC   -> Openssl3AesCbc
        AES.GCM   -> Openssl3AesGcm
        ECDSA     -> Openssl3Ecdsa
        RSA.PSS   -> Openssl3RsaPss
        RSA.PKCS1 -> Openssl3RsaPkcs1
        RSA.OAEP  -> Openssl3RsaOaep
        else      -> null
    } as A?
}

@Suppress("DEPRECATION", "INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = registerProvider(defaultProvider)
