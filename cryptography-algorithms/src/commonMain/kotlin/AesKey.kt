/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.algorithms.BinarySize.Companion.bits
import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.bytestring.*

public interface AesKey : SecretKey, CryptographyComponent<AesKey> {
    public interface Tag<I : Any, P : Any> : CryptographyComponent.Tag<AesKey, I, P>
}

public object AesKeySize {
    public val B256: BinarySize get() = 256.bits
}

public class AesKeyGenerationParameters(public val size: Int) {
    public companion object {
        public val B256: AesKeyGenerationParameters = AesKeyGenerationParameters(256)
    }
}

// TODO: make `nonce` single-use?
public class AesGcmCipherParameters(
    public val nonce: ByteString,
    public val tagSize: BinarySize,
)
