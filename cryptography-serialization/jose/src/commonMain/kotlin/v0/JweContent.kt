/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JweContent : JoseContent {
    public val authenticatedData: ByteArray?

    public val sharedHeader: JweCompositeHeader
    public val recipientHeaders: List<JweHeader>

    public sealed interface Compact : JweContent, JoseContent.Compact {
        override val header: JweHeader

        // always null
        override val authenticatedData: ByteArray?

        // has only protected part equals to `header`
        override val sharedHeader: JweCompositeHeader

        // single empty header
        override val recipientHeaders: List<JweHeader>
    }
}

public fun jweContent(
    header: JweHeader,
    payload: ByteArray,
): JweContent.Compact = TODO()

public fun jweContent(
    sharedHeader: JweCompositeHeader,
    recipientHeaders: List<JweHeader>,
    payload: ByteArray,
    authenticatedData: ByteArray?,
): JweContent = TODO()
