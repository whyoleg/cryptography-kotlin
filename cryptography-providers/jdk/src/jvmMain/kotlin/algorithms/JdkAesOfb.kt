/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*

internal class JdkAesOfb(
    private val state: JdkCryptographyState,
) : AES.OFB {
    private val keyWrapper: (JSecretKey) -> AES.OFB.Key = { key -> JdkAesOfbKey(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): Decoder<AES.Key.Format, AES.OFB.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.OFB.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesOfbKey(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.OFB.Key, JdkEncodableKey<AES.Key.Format>(key) {
    override fun cipher(): IvCipher = JdkAesIvCipher(
        state = state,
        key = key,
        ivSize = 16,
        algorithm = "AES/OFB/NoPadding"
    )

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
    }
}
