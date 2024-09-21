/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.functions

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

public interface SignFunction : UpdateFunction {
    public fun signIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int
    public fun signToByteArray(): ByteArray
    public fun sign(): ByteString = signToByteArray().asByteString()
}
