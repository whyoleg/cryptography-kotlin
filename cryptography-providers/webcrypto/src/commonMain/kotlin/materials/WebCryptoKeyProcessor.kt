/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*

internal abstract class WebCryptoKeyProcessor<KF : KeyFormat> {
    abstract fun stringFormat(format: KF): String
    abstract fun beforeDecoding(format: KF, key: ByteArray): ByteArray
    abstract fun afterEncoding(format: KF, key: ByteArray): ByteArray
}

