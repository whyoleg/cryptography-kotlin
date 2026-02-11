/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkAesCtr(
    private val state: JdkCryptographyState,
) : AES.CTR, BaseAes<AES.CTR.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CTR.Key = AesCtrKey(rawKey)

    private inner class AesCtrKey(rawKey: ByteArray) : AES.CTR.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "AES")

        override fun cipher(): IvCipher = JdkAesIvCipher(
            state = state,
            key = secretKey,
            ivSize = 16,
            algorithm = "AES/CTR/NoPadding"
        )
    }
}
