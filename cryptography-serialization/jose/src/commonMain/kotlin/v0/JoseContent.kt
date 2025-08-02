/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// TODO: may be it's also possible to add `sharedHeader` and `customHeaders`,
//  but not sure if it's needed
public sealed interface JoseContent {
    public val payload: ByteArray

    public sealed interface Compact : JoseContent {
        public val header: JoseHeader // protected only
    }
}
