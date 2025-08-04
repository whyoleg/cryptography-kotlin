/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// alg
public class JweAlgorithm(override val value: String) : JoseAlgorithm {
    public companion object {
        // public val HS256: Algorithm = Algorithm("HS256")
    }
}

// enc
public class JweContentEncryptionAlgorithm(public val value: String) {
    public companion object {
        // public val HS256: Algorithm = Algorithm("HS256")
    }
}

public sealed interface JweHeader : JoseHeader {
    public override val algorithm: JweAlgorithm?
    public val encryptionAlgorithm: JweContentEncryptionAlgorithm

    public operator fun plus(other: JweHeader): JweHeader

    public companion object {
        public val Empty: JweHeader = TODO()
    }
}

public sealed interface JweHeaderBuilder : JoseHeaderBuilder, JweHeader {
    public override var algorithm: JweAlgorithm?
    public override var encryptionAlgorithm: JweContentEncryptionAlgorithm

    public fun fromHeader(header: JweHeader)
}

public inline fun jweHeader(builderAction: JweHeaderBuilder.() -> Unit): JweHeader = TODO()

public inline fun jweHeader(
    algorithm: JweAlgorithm,
    encryptionAlgorithm: JweContentEncryptionAlgorithm,
    builderAction: JweHeaderBuilder.() -> Unit,
): JweHeader = TODO()

public sealed interface JweHeaders : JoseHeaders {
    override val protected: JweHeader
    override val unprotected: JweHeader

    override val combined: JweHeader
}

public sealed interface JweHeadersBuilder : JweHeaders, JoseHeadersBuilder {
    override val protected: JweHeaderBuilder
    override val unprotected: JweHeaderBuilder

    public fun fromHeaders(headers: JweHeaders)
}

public inline fun jweHeaders(builderAction: JweHeadersBuilder.() -> Unit): JweHeaders = TODO()

// algorithm will be used for protected header
public inline fun jweHeaders(
    algorithm: JweAlgorithm,
    encryptionAlgorithm: JweContentEncryptionAlgorithm,
    builderAction: JweHeadersBuilder.() -> Unit,
): JweHeaders = TODO()
