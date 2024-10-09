/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.apple.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import platform.CoreCrypto.*

internal object CCHkdf : BaseHkdf(AppleCryptographyProvider) {
    override fun digestSize(digest: CryptographyAlgorithmId<Digest>): Int {
        return when (digest) {
            SHA1   -> CC_SHA1_DIGEST_LENGTH
            SHA224 -> CC_SHA224_DIGEST_LENGTH
            SHA256 -> CC_SHA256_DIGEST_LENGTH
            SHA384 -> CC_SHA384_DIGEST_LENGTH
            SHA512 -> CC_SHA512_DIGEST_LENGTH
            else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
        }
    }
}
