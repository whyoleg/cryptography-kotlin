/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.bouncycastle.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import org.bouncycastle.crypto.generators.*
import org.bouncycastle.crypto.params.*

internal object BcHkdf : HKDF {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray?,
    ): SecretDerivation {

        TODO("Not yet implemented")
    }

}

private class BcHkdfSecretDerivation(
    private val generator: HKDFBytesGenerator,
    private val outputSizeBytes: Int,
    private val salt: ByteArray?,
    private val info: ByteArray?,
) : SecretDerivation {
    override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray {
        generator.init(
            HKDFParameters(
                /* ikm = */ input,
                /* salt = */ salt,
                /* info = */ info
            )
        )
        TODO("Not yet implemented")
    }
}
