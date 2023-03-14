/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.apple

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.apple.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*

private val defaultProvider = lazy { AppleCryptographyProvider }

public val CryptographyProvider.Companion.Apple: CryptographyProvider by defaultProvider

internal object AppleCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "Apple"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        MD5     -> CCDigest(CCHashAlgorithm.MD5, MD5)
        SHA1    -> CCDigest(CCHashAlgorithm.SHA1, SHA1)
        SHA256  -> CCDigest(CCHashAlgorithm.SHA256, SHA256)
        SHA384  -> CCDigest(CCHashAlgorithm.SHA384, SHA384)
        SHA512  -> CCDigest(CCHashAlgorithm.SHA512, SHA512)
        HMAC    -> CCHmac
        AES.CBC -> CCAesCbc
        else    -> null
    } as A?
}

@Suppress("DEPRECATION", "INVISIBLE_MEMBER")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = registerProvider(defaultProvider)
