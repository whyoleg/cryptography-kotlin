/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*

internal class JdkHkdf(
    private val state: JdkCryptographyState,
    provider: CryptographyProvider,
) : BaseHkdf(provider) {
    override fun digestSize(digest: CryptographyAlgorithmId<Digest>): Int {
        return state.messageDigest(digest.name).use { it.digestLength }
    }
}
