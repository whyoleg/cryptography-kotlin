/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.functions

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

public interface VerifyFunction : UpdateFunction {
    public fun verify(signature: ByteArray, startIndex: Int = 0, endIndex: Int = signature.size): Boolean
    public fun verify(signature: ByteString, startIndex: Int = 0, endIndex: Int = signature.size): Boolean =
        verify(signature.asByteArray(), startIndex, endIndex)

    public fun reset()
}
