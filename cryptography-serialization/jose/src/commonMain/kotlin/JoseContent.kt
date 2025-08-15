/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

public sealed interface JoseContent {
    public val payload: ByteArray

    public sealed interface Compact : JoseContent {
        public val header: JoseHeader // protected only
    }
}
