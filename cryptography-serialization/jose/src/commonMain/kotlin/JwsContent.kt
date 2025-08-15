/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

public sealed interface JwsContent : JoseContent {
    public val signatureHeaders: List<JwsHeaders>

    public sealed interface Compact : JwsContent, JoseContent.Compact {
        override val header: JwsHeader

        // single header, with protected part equals to `header`
        override val signatureHeaders: List<JwsHeaders>
    }
}

@Suppress("FunctionName")
public fun JwsContent(
    protectedHeader: JwsHeader,
    payload: ByteArray,
): JwsContent.Compact = TODO()

public fun JwsContent(
    signatureHeaders: List<JwsHeaders>,
    payload: ByteArray,
): JwsContent = TODO()
