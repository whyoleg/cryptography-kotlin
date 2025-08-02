/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JoseObject {
    public fun toJsonString(
        /*named*/preferFlattened: Boolean = false,
        /*named*/detachedContent: Boolean = false,
    ): String

    public sealed interface Compact : JoseObject {
        public val header: JoseHeader

        // TODO: what could be a good name for this flag? it means signature payload or encrypted key
        public fun toCompactString(/*named*/detachedContent: Boolean = false): String
    }

    public companion object {
        public fun parseCompactString(string: String): Compact = TODO()
        public fun parseCompactString(string: String, detachedContent: ByteArray): Compact = TODO()
        public fun parseJsonString(string: String): JoseObject = TODO()
    }
}
