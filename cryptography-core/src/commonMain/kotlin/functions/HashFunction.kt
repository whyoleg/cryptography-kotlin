/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.functions

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

public interface HashFunction : UpdateFunction {
    public fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int
    public fun hashToByteArray(): ByteArray
    public fun hash(): ByteString = hashToByteArray().asByteString()
    public fun reset()
}
