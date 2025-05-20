/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.apple.algorithms.*

private val defaultProvider = lazy { AppleCryptographyProvider }

public val CryptographyProvider.Companion.Apple: CryptographyProvider by defaultProvider

internal object AppleCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "Apple"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        MD5       -> CCDigest(CCHashAlgorithm.MD5, MD5)
        SHA1      -> CCDigest(CCHashAlgorithm.SHA1, SHA1)
        SHA224    -> CCDigest(CCHashAlgorithm.SHA224, SHA224)
        SHA256    -> CCDigest(CCHashAlgorithm.SHA256, SHA256)
        SHA384    -> CCDigest(CCHashAlgorithm.SHA384, SHA384)
        SHA512    -> CCDigest(CCHashAlgorithm.SHA512, SHA512)
        HMAC    -> CCHmac
        AES.CBC -> CCAesCbc
        AES.CTR -> CCAesCtr
        AES.ECB -> CCAesEcb
        RSA.PSS -> SecRsaPss
        RSA.PKCS1 -> SecRsaPkcs1
        RSA.OAEP  -> SecRsaOaep
        RSA.RAW -> SecRsaRaw
        ECDSA   -> SecEcdsa
        PBKDF2  -> CCPbkdf2
        HKDF -> CCHkdf
        else      -> null
    } as A?
}

@Suppress("DEPRECATION")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = CryptographySystem.registerProvider(defaultProvider, 120)
