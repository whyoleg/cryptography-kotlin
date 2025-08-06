/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*

@Serializable
public sealed interface JweHeader : JoseHeader {
    public val algorithm: JweAlgorithm?
    public val encryptionAlgorithm: JweEncryptionAlgorithm

    public operator fun plus(other: JweHeader): JweHeader

    public companion object {
        public val Empty: JweHeader = TODO()
    }
}

public sealed interface JweHeaderBuilder : JoseHeaderBuilder, JweHeader {
    public override var algorithm: JweAlgorithm?
    public override var encryptionAlgorithm: JweEncryptionAlgorithm
}

public inline fun JweHeader(builderAction: JweHeaderBuilder.() -> Unit): JweHeader = TODO()

public inline fun JweHeader(
    algorithm: JweAlgorithm,
    encryptionAlgorithm: JweEncryptionAlgorithm,
    builderAction: JweHeaderBuilder.() -> Unit,
): JweHeader = TODO()

public sealed interface JweHeaders : JoseHeaders {
    override val protected: JweHeader
    override val unprotected: JweHeader

    override val combined: JweHeader

    public operator fun plus(other: JweHeaders): JweHeaders

    public companion object {
        public val Empty: JweHeaders = TODO()
    }
}

public sealed interface JweHeadersBuilder : JweHeaders, JoseHeadersBuilder {
    override val protected: JweHeaderBuilder
    override val unprotected: JweHeaderBuilder
}

public inline fun JweHeaders(builderAction: JweHeadersBuilder.() -> Unit): JweHeaders = TODO()

// algorithm will be used for protected header
public inline fun JweHeaders(
    algorithm: JweAlgorithm,
    encryptionAlgorithm: JweEncryptionAlgorithm,
    builderAction: JweHeadersBuilder.() -> Unit,
): JweHeaders = TODO()
