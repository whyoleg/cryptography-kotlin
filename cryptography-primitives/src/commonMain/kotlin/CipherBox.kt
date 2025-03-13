/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives

import kotlinx.io.bytestring.*

public interface CipherBox {
    public val combined: ByteString
}

public interface Signature {
    // TODO: better name
    public val defaultRepresentation: ByteString
}
