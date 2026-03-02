/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesEcb(
    private val state: JdkCryptographyState,
) : AES.ECB, BaseAes<AES.ECB.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.ECB.Key = AesEcbKey(rawKey)

    private inner class AesEcbKey(rawKey: ByteArray) : AES.ECB.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "AES")

        override fun cipher(padding: Boolean): Cipher = JdkAesEcbCipher(
            state = state,
            key = secretKey,
            algorithm = when {
                padding -> "AES/ECB/PKCS5Padding"
                else    -> "AES/ECB/NoPadding"
            }
        )
    }
}

private class JdkAesEcbCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    algorithm: String,
) : BaseCipher {
    private val cipher = state.cipher(algorithm)

    override fun createEncryptFunction(): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, state.secureRandom)
        })
    }

    override fun createDecryptFunction(): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, state.secureRandom)
        })
    }
}
