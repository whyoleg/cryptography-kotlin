/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal abstract class WebCryptoAes<K : AES.Key>(
    private val algorithmName: String,
    private val keyWrapper: WebCryptoKeyWrapper<K>,
) : AES<K> {
    final override fun keyDecoder(): KeyDecoder<AES.Key.Format, K> = WebCryptoKeyDecoder(
        algorithm = Algorithm(algorithmName),
        keyProcessor = AesKeyProcessor,
        keyWrapper = keyWrapper
    )

    final override fun keyGenerator(keySize: BinarySize): KeyGenerator<K> = WebCryptoSymmetricKeyGenerator(
        algorithm = AesKeyGenerationAlgorithm(algorithmName, keySize.inBits),
        keyWrapper = keyWrapper
    )

    protected abstract class AesKey(protected val key: CryptoKey) : WebCryptoEncodableKey<AES.Key.Format>(
        key = key,
        keyProcessor = AesKeyProcessor
    ), AES.Key
}

private object AesKeyProcessor : WebCryptoKeyProcessor<AES.Key.Format>() {
    override fun stringFormat(format: AES.Key.Format): String = when (format) {
        AES.Key.Format.RAW -> "raw"
        AES.Key.Format.JWK -> "jwk"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: AES.Key.Format, key: ByteArray): ByteArray = key
    override fun afterEncoding(format: AES.Key.Format, key: ByteArray): ByteArray = key
}
