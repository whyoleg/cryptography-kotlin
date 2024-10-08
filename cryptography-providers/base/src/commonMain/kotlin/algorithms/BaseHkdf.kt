/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import kotlin.math.*

@CryptographyProviderApi
public abstract class BaseHkdf(provider: CryptographyProvider) : HKDF {
    private val hmac = provider.get(HMAC)

    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray?,
    ): SecretDerivation {
        val digestSize = digestSize(digest)
        return HkdfSecretDerivation(
            decoder = hmac.keyDecoder(digest),
            digestSize = digestSize,
            outputSize = outputSize,
            salt = salt?.takeIf(ByteArray::isNotEmpty) ?: ByteArray(digestSize),
            info = info?.takeIf(ByteArray::isNotEmpty) ?: EmptyByteArray,
        )
    }

    protected abstract fun digestSize(digest: CryptographyAlgorithmId<Digest>): Int

    private class HkdfSecretDerivation(
        private val decoder: KeyDecoder<HMAC.Key.Format, HMAC.Key>,
        private val digestSize: Int,
        private val outputSize: BinarySize,
        private val salt: ByteArray,
        private val info: ByteArray,
    ) : SecretDerivation {

        override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray {
            val iterations = ceil(outputSize.inBytes.toDouble() / digestSize).toInt()
            require(iterations <= 255) { "out length must be maximal 255 * hash-length; requested: $outputSize" }

            val pseudoRandomKey = decoder.decodeFromByteArrayBlocking(HMAC.Key.Format.RAW, salt)
                .signatureGenerator()
                .generateSignatureBlocking(input)

            val function =
                decoder.decodeFromByteArrayBlocking(HMAC.Key.Format.RAW, pseudoRandomKey)
                    .signatureGenerator()
                    .createSignFunction()

            /**
             * The output `OKM` is calculated as follows:
             *
             *    N = ceil(L/HashLen) (iterations)
             *    T = T(1) | T(2) | T(3) | ... | T(N) (block)
             *    OKM = first L octets of T (output)
             *
             *    where:
             *    T(0) = empty string (zero length)
             *    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
             *    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
             *    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
             *    ...
             */
            var output = EmptyByteArray
            var t = EmptyByteArray
            val iterationArray = ByteArray(1)
            repeat(iterations) { iteration ->
                function.update(t)
                function.update(info)
                iterationArray[0] = (iteration + 1).toByte()
                function.update(iterationArray)

                t = function.signToByteArray()
                output += t
            }

            return output.ensureSizeExactly(outputSize.inBytes)
        }
    }
}
