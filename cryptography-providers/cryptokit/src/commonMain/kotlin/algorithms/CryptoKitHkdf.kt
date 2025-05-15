/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import kotlinx.cinterop.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitHkdf : HKDF {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray?,
    ): SecretDerivation = HkdfSecretDerivation(
        algorithm = when (digest) {
            MD5    -> SwiftHashAlgorithmMd5
            SHA1   -> SwiftHashAlgorithmSha1
            SHA256 -> SwiftHashAlgorithmSha256
            SHA384 -> SwiftHashAlgorithmSha384
            SHA512 -> SwiftHashAlgorithmSha512
            else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
        },
        outputSize = outputSize,
        salt = salt ?: EmptyByteArray,
        info = info ?: EmptyByteArray
    )
}

@OptIn(UnsafeNumber::class)
private class HkdfSecretDerivation(
    private val algorithm: SwiftHashAlgorithm,
    private val outputSize: BinarySize,
    private val salt: ByteArray,
    private val info: ByteArray,
) : SecretDerivation {
    override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray {
        return input.useNSData { ikm ->
            salt.useNSData { salt ->
                info.useNSData { info ->
                    SwiftHkdf.deriveWithAlgorithm(
                        algorithm = algorithm,
                        inputKey = ikm,
                        salt = salt,
                        info = info,
                        outputSize = outputSize.inBytes.convert()
                    ).toByteArray()
                }
            }
        }
    }
}
