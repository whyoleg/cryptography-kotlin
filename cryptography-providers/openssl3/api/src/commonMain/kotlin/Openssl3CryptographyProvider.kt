/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.DH
import dev.whyoleg.cryptography.providers.openssl3.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

private val defaultProvider = lazy { Openssl3CryptographyProvider }

public val CryptographyProvider.Companion.Openssl3: CryptographyProvider by defaultProvider

internal object Openssl3CryptographyProvider : CryptographyProvider() {
    override val name: String = "OpenSSL3 (${OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString() ?: "unknown"})"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        MD5              -> Openssl3Digest("MD5", MD5)
        SHA1             -> Openssl3Digest("SHA1", SHA1)
        SHA224           -> Openssl3Digest("SHA224", SHA224)
        SHA256           -> Openssl3Digest("SHA256", SHA256)
        SHA384           -> Openssl3Digest("SHA384", SHA384)
        SHA512           -> Openssl3Digest("SHA512", SHA512)
        SHA3_224         -> Openssl3Digest("SHA3-224", SHA3_224)
        SHA3_256         -> Openssl3Digest("SHA3-256", SHA3_256)
        SHA3_384         -> Openssl3Digest("SHA3-384", SHA3_384)
        SHA3_512         -> Openssl3Digest("SHA3-512", SHA3_512)
        RIPEMD160        -> Openssl3Digest("RIPEMD160", RIPEMD160)
        HMAC             -> Openssl3Hmac
        AES.CBC          -> Openssl3AesCbc
        AES.CFB8         -> Openssl3AesCfb8
        AES.CMAC         -> Openssl3AesCmac
        AES.CTR          -> Openssl3AesCtr
        AES.CFB          -> Openssl3AesCfb
        AES.OFB          -> Openssl3AesOfb
        AES.ECB          -> Openssl3AesEcb
        AES.GCM          -> Openssl3AesGcm
        AES.CCM -> Openssl3AesCcm
        ChaCha20Poly1305 -> Openssl3ChaCha20Poly1305
        ECDSA            -> Openssl3Ecdsa
        DSA              -> Openssl3Dsa
        ECDH             -> Openssl3Ecdh
        EdDSA -> Openssl3EdDsa
        XDH   -> Openssl3Xdh
        DH -> Openssl3Dh
        RSA.PSS          -> Openssl3RsaPss
        RSA.PKCS1        -> Openssl3RsaPkcs1
        RSA.OAEP         -> Openssl3RsaOaep
        RSA.RAW          -> Openssl3RsaRaw
        PBKDF2           -> Openssl3Pbkdf2
        HKDF             -> Openssl3Hkdf
        else             -> null
    } as A?
}

@Suppress("DEPRECATION")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = CryptographySystem.registerProvider(defaultProvider, 100)
