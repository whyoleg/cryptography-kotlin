/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import javax.crypto.spec.*

internal class JdkAesCtr(
    private val state: JdkCryptographyState,
) : AES.CTR {
    private val keyWrapper: (JSecretKey) -> AES.CTR.Key = { key -> JdkAesCtrKey(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): Decoder<AES.Key.Format, AES.CTR.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.CTR.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesCtrKey(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.CTR.Key, JdkEncodableKey<AES.Key.Format>(key) {
    override fun cipher(): IvCipher = JdkAesIvCipher(
        state = state,
        key = key,
        ivSize = 16,
        algorithm = "AES/CTR/NoPadding"
    )

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
    }
}