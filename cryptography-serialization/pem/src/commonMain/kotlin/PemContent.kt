/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

public class PemContent(
    public val label: PemLabel,
    public val bytes: ByteArray,
) {
    public constructor(
        label: PemLabel,
        byteString: ByteString,
    ) : this(label, byteString.toByteArray())

    @OptIn(UnsafeByteStringApi::class)
    public val byteString: ByteString get() = UnsafeByteStringOperations.wrapUnsafe(bytes)
}

public fun PemContent.ensurePemLabel(label: PemLabel): PemContent {
    check(this.label == label) { "Wrong PEM label, expected $label, actual ${this.label}" }
    return this
}
