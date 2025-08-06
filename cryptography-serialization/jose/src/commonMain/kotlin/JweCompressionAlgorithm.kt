/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlin.jvm.*

@Serializable
@JvmInline
public value class JweCompressionAlgorithm(public val name: String) {
    public companion object {
        public val DEFLATE: JweCompressionAlgorithm = JweCompressionAlgorithm("DEF")
    }
}
