/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JweCompositeHeader : JoseCompositeHeader {
    override val protected: JweHeader
    override val unprotected: JweHeader

    override val combined: JweHeader
}

public sealed interface JweCompositeHeaderBuilder : JweCompositeHeader, JoseCompositeHeaderBuilder {
    override val protected: JweHeaderBuilder
    override val unprotected: JweHeaderBuilder

    public fun fromCompositeHeader(header: JweCompositeHeader)
}

public inline fun jweCompositeHeader(builderAction: JweCompositeHeaderBuilder.() -> Unit): JweCompositeHeader = TODO()

// algorithm will be used for protected header
public inline fun jweCompositeHeader(
    algorithm: JweHeader.Algorithm,
    encryptionAlgorithm: JweHeader.EncryptionAlgorithm,
    builderAction: JweCompositeHeaderBuilder.() -> Unit,
): JweCompositeHeader = TODO()
