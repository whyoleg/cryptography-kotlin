/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal object WebCryptoHkdf : HKDF {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray?,
    ): SecretDerivation = HkdfSecretDerivation(
        HkdfDeriveAlgorithm(
            hash = digest.hashAlgorithmName(),
            salt = salt?.takeIf(ByteArray::isNotEmpty) ?: ByteArray(digest.digestSize()),
            info = info?.takeIf(ByteArray::isNotEmpty) ?: EmptyByteArray
        ),
        outputSize
    )

    private class HkdfSecretDerivation(
        private val algorithm: Algorithm,
        private val outputSize: BinarySize,
    ) : SecretDerivation {
        override suspend fun deriveSecretToByteArray(input: ByteArray): ByteArray {
            val inputKey = WebCrypto.importKey(
                format = "raw",
                keyData = input,
                algorithm = Algorithm("HKDF"),
                extractable = false,
                keyUsages = arrayOf("deriveBits")
            )
            return WebCrypto.deriveBits(
                algorithm = algorithm,
                baseKey = inputKey,
                length = outputSize.inBits
            )
        }

        override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray = nonBlocking()
    }
}
