/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal abstract class WebCryptoKeyProcessor<F : EncodingFormat> {
    abstract fun stringFormat(format: F): String
    abstract fun beforeDecoding(algorithm: Algorithm, format: F, key: ByteArray): ByteArray
    abstract fun afterEncoding(algorithm: Algorithm, format: F, key: ByteArray): ByteArray
}

