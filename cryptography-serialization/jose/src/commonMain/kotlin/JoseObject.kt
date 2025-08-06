/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

public sealed interface JoseObject {
    public fun toJsonString(/*named*/preferFlattened: Boolean = false): String

    public sealed interface Compact : JoseObject {
        public val header: JoseHeader

        public fun toCompactString(): String
    }

    public companion object {
        public fun parseCompactString(string: String): Compact = TODO()
        public fun parseJsonString(string: String): JoseObject = TODO()
    }
}
