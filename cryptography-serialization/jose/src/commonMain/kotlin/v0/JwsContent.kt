/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JwsContent : JoseContent {
    public val signatureHeaders: List<JwsHeaders>

    public sealed interface Compact : JwsContent, JoseContent.Compact {
        override val header: JwsHeader

        // single header, with protected part equals to `header`
        override val signatureHeaders: List<JwsHeaders>
    }
}

// TODO: may be add overloads for string?json?etc?
public fun jwsContent(
    protectedHeader: JwsHeader,
    payload: ByteArray,
): JwsContent.Compact = TODO()

public fun jwsContent(
    signatureHeaders: List<JwsHeaders>,
    payload: ByteArray,
): JwsContent = TODO()
