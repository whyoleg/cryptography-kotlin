/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public class JwsAlgorithm(override val value: String) : JoseAlgorithm {
    public companion object {
        public val HS256: JwsAlgorithm = JwsAlgorithm("HS256")
    }
}

public sealed interface JwsHeader : JoseHeader {
    public override val algorithm: JwsAlgorithm?

    public operator fun plus(other: JwsHeader): JwsHeader

    public companion object {
        public val Empty: JwsHeader = TODO()
    }
}

public sealed interface JwsHeaderBuilder : JoseHeaderBuilder, JwsHeader {
    override var algorithm: JwsAlgorithm?

    public fun fromHeader(header: JwsHeader)
}

public inline fun jwsHeader(builderAction: JwsHeaderBuilder.() -> Unit): JwsHeader = TODO()

public inline fun jwsHeader(
    algorithm: JwsAlgorithm,
    builderAction: JwsHeaderBuilder.() -> Unit,
): JwsHeader = TODO()

public sealed interface JwsHeaders : JoseHeaders {
    override val protected: JwsHeader
    override val unprotected: JwsHeader

    override val combined: JwsHeader
}

public sealed interface JwsHeadersBuilder : JwsHeaders, JoseHeadersBuilder {
    override val protected: JwsHeaderBuilder
    override val unprotected: JwsHeaderBuilder

    public fun fromHeaders(headers: JwsHeaders)
}

public inline fun jwsHeaders(builderAction: JwsHeadersBuilder.() -> Unit): JwsHeaders = TODO()

// algorithm will be used for protected header
public inline fun jwsHeaders(
    algorithm: JwsAlgorithm,
    builderAction: JwsHeadersBuilder.() -> Unit,
): JwsHeaders = TODO()
