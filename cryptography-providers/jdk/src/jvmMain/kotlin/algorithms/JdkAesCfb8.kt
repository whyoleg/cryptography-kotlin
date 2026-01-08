/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*

internal class JdkAesCfb8(
    private val state: JdkCryptographyState,
) : AES.CFB8 {
    private val keyWrapper: (JSecretKey) -> AES.CFB8.Key = { key -> JdkAesCfb8Key(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CFB8.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.CFB8.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesCfb8Key(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.CFB8.Key, JdkEncodableKey<AES.Key.Format>(key) {
    override fun cipher(): AES.IvCipher = JdkAesIvCipher(
        state = state,
        key = key,
        ivSize = 16,
        algorithm = "AES/CFB8/NoPadding"
    )

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
    }
}
