/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkAesCfb(
    private val state: JdkCryptographyState,
) : AES.CFB, BaseAes<AES.CFB.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CFB.Key = AesCfbKey(rawKey)

    private inner class AesCfbKey(rawKey: ByteArray) : AES.CFB.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "AES")

        override fun cipher(): IvCipher = JdkAesIvCipher(
            state = state,
            key = secretKey,
            ivSize = 16,
            algorithm = "AES/CFB/NoPadding"
        )
    }
}
