/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JweContent : JoseContent {
    public val authenticatedData: ByteArray?

    public val sharedHeaders: JweHeaders
    public val recipientHeaders: List<JweHeader>

    public sealed interface Compact : JweContent, JoseContent.Compact {
        override val header: JweHeader

        // always null
        override val authenticatedData: ByteArray?

        // has only protected part equals to `header`
        override val sharedHeaders: JweHeaders

        // single empty header
        override val recipientHeaders: List<JweHeader>
    }
}

public fun jweContent(
    protectedHeader: JweHeader,
    payload: ByteArray,
): JweContent.Compact = TODO()

public fun jweContent(
    sharedHeaders: JweHeaders,
    recipientHeaders: List<JweHeader>,
    payload: ByteArray,
    authenticatedData: ByteArray?,
): JweContent = TODO()
