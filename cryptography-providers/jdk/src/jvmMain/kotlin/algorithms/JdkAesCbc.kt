/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*

internal class JdkAesCbc(
    private val state: JdkCryptographyState,
) : AES.CBC {
    private val keyWrapper: (JSecretKey) -> AES.CBC.Key = { key -> JdkAesCbcKey(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.CBC.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesCbcKey(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.CBC.Key, JdkEncodableKey<AES.Key.Format>(key) {
    override fun cipher(padding: Boolean): AES.IvCipher = JdkAesIvCipher(
        state = state,
        key = key,
        ivSize = 16,
        algorithm = when {
            padding -> "AES/CBC/PKCS5Padding"
            else    -> "AES/CBC/NoPadding"
        }
    )

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
    }
}
