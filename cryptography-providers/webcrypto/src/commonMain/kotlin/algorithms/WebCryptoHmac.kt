/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoHmac : HMAC {
    private val keyUsages = arrayOf("sign", "verify")
    private val keyFormat: (HMAC.Key.Format) -> String = {
        when (it) {
            HMAC.Key.Format.RAW -> "raw"
            HMAC.Key.Format.JWK -> "jwk"
        }
    }
    private val keyWrapper: (CryptoKey) -> HMAC.Key = { key ->
        val algorithm = Algorithm("HMAC")
        object : HMAC.Key, EncodableKey<HMAC.Key.Format> by WebCryptoEncodableKey(key, keyFormat) {
            private val generator = WebCryptoSignatureGenerator(algorithm, key)
            private val verifier = WebCryptoSignatureVerifier(algorithm, key)
            override fun signatureGenerator(): SignatureGenerator = generator
            override fun signatureVerifier(): SignatureVerifier = verifier
        }
    }

    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> =
        WebCryptoKeyDecoder(HmacKeyAlgorithm(digest.hashAlgorithmName(), digest.blockSize()), keyUsages, keyFormat, keyWrapper)

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> =
        WebCryptoSymmetricKeyGenerator(HmacKeyAlgorithm(digest.hashAlgorithmName(), digest.blockSize()), keyUsages, keyWrapper)
}
