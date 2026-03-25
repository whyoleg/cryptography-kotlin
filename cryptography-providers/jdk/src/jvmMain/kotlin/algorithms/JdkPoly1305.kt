/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

private const val keySize: Int = 32

internal class JdkPoly1305(
    private val state: JdkCryptographyState,
) : Poly1305 {
    private val algorithm = "Poly1305"
    private val keyWrapper: (JSecretKey) -> Poly1305.Key = { key -> JdkPoly1305Key(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<Poly1305.Key.Format, _>(algorithm, keyWrapper)

    override fun keyDecoder(): Decoder<Poly1305.Key.Format, Poly1305.Key> = keyDecoder
    override fun keyGenerator(): KeyGenerator<Poly1305.Key> = JdkSecretKeyGenerator(state, algorithm, keyWrapper) {
        init(keySize * 8, state.secureRandom)
    }
}

private class JdkPoly1305Key(
    state: JdkCryptographyState,
    key: JSecretKey,
) : Poly1305.Key, JdkEncodableKey<Poly1305.Key.Format>(key) {
    private val signature = JdkMacSignature(state, key, "Poly1305")

    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: Poly1305.Key.Format): ByteArray = when (format) {
        Poly1305.Key.Format.RAW -> encodeToRaw()
    }
}
