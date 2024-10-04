/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesEcb(
    private val state: JdkCryptographyState,
) : AES.ECB {
    private val keyWrapper: (JSecretKey) -> AES.ECB.Key = { key -> JdkAesEcbKey(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.ECB.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.ECB.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesEcbKey(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.ECB.Key, JdkEncodableKey<AES.Key.Format>(key) {
    override fun cipher(padding: Boolean): Cipher = JdkAesEcbCipher(
        state = state,
        key = key,
        algorithm = when {
            padding -> "AES/ECB/PKCS5Padding"
            else    -> "AES/ECB/NoPadding"
        }
    )

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
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
