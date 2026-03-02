/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkAesCbc(
    private val state: JdkCryptographyState,
) : AES.CBC, BaseAes<AES.CBC.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CBC.Key = AesCbcKey(rawKey)

    private inner class AesCbcKey(rawKey: ByteArray) : AES.CBC.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "AES")

        override fun cipher(padding: Boolean): IvCipher = JdkAesIvCipher(
            state = state,
            key = secretKey,
            ivSize = 16,
            algorithm = when {
                padding -> "AES/CBC/PKCS5Padding"
                else    -> "AES/CBC/NoPadding"
            }
        )
    }
}
