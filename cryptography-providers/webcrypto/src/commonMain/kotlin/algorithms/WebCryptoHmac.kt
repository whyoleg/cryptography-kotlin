/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoHmac : HMAC {
    private val keyWrapper: WebCryptoKeyWrapper<HMAC.Key> = WebCryptoKeyWrapper(arrayOf("sign", "verify"), ::HmacKey)
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> = WebCryptoKeyDecoder(
        algorithm = HmacKeyAlgorithm(digest.hashAlgorithmName(), digest.blockSize()),
        keyProcessor = HmacKeyProcessor,
        keyWrapper = keyWrapper,
    )

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> = WebCryptoSymmetricKeyGenerator(
        algorithm = HmacKeyAlgorithm(digest.hashAlgorithmName(), digest.blockSize()),
        keyWrapper = keyWrapper
    )

    private class HmacKey(private val key: CryptoKey) : WebCryptoEncodableKey<HMAC.Key.Format>(
        key = key,
        keyProcessor = HmacKeyProcessor
    ), HMAC.Key {
        override fun signatureGenerator(): SignatureGenerator = WebCryptoSignatureGenerator(Algorithm("HMAC"), key)
        override fun signatureVerifier(): SignatureVerifier = WebCryptoSignatureVerifier(Algorithm("HMAC"), key)
    }

}

private object HmacKeyProcessor : WebCryptoKeyProcessor<HMAC.Key.Format>() {
    override fun stringFormat(format: HMAC.Key.Format): String = when (format) {
        HMAC.Key.Format.RAW -> "raw"
        HMAC.Key.Format.JWK -> "jwk"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: HMAC.Key.Format, key: ByteArray): ByteArray = key
    override fun afterEncoding(format: HMAC.Key.Format, key: ByteArray): ByteArray = key
}
