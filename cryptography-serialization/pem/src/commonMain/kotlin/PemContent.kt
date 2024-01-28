/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

public class PemContent(
    public val label: PemLabel,
    public val bytes: ByteArray,
)

public fun PemContent.ensurePemLabel(label: PemLabel): PemContent {
    check(this.label == label) { "Wrong PEM label, expected $label, actual ${this.label}" }
    return this
}
