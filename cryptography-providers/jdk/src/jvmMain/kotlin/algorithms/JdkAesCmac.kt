/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

internal class JdkAesCmac(
    private val state: JdkCryptographyState,
) : AES.CMAC {
    private val algorithm = "AESCMAC"
    private val keyWrapper: (JSecretKey) -> AES.CMAC.Key = { key -> JdkAesCmacKey(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>(algorithm, keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CMAC.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.CMAC.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesCmacKey(
    state: JdkCryptographyState,
    key: JSecretKey,
) : AES.CMAC.Key, JdkEncodableKey<AES.Key.Format>(key) {
    private val algorithm = "AESCMAC"
    private val signature = JdkMacSignature(state, key, algorithm)

    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
    }
}