/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.core

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.primitives.core.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*

public interface AesKeyFactory : SecretKeyFactory<AesKey> {
    public fun generate(size: BinarySize = AesKeySize.B256): AesKey

    public companion object Tag : CryptographyProvider.Tag<AesKeyFactory, Unit>
}

//public interface HmacKeyFactory {
//    public fun generate(digest: DigestAlgorithm, size: BinarySize)
//}

public interface AesGcmCipher : BoxCipherPrimitive<AesGcmCipherParameters, AesGcmCipherBox> {
    public override fun encryptToBox(plaintext: ByteString): AesGcmCipherBox {
        // random + default
        val parameters = AesGcmCipherParameters(
            nonce = ByteString(CryptographyRandom.nextBytes(AesGcmCipherBox.NONCE_SIZE.inBytes)),
            tagSize = AesGcmCipherBox.DEFAULT_TAG_SIZE
        )
        return encryptToBox(plaintext, parameters)
    }

    public companion object Tag : AesKey.Tag<AesGcmCipher, Unit>
}
