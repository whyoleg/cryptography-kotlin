/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*

@Serializable
public sealed interface JwsHeader : JoseHeader {
    public val algorithm: JwsAlgorithm?

    public operator fun plus(other: JwsHeader): JwsHeader

    public companion object {
        public val Empty: JwsHeader = TODO()
    }
}

public sealed interface JwsHeaderBuilder : JoseHeaderBuilder, JwsHeader {
    override var algorithm: JwsAlgorithm?
}

public inline fun JwsHeader(builderAction: JwsHeaderBuilder.() -> Unit): JwsHeader = TODO()

public inline fun JwsHeader(
    algorithm: JwsAlgorithm,
    builderAction: JwsHeaderBuilder.() -> Unit,
): JwsHeader = TODO()

public sealed interface JwsHeaders : JoseHeaders {
    override val protected: JwsHeader
    override val unprotected: JwsHeader

    override val combined: JwsHeader

    // protected + protected, unprotected + unprotected
    public operator fun plus(other: JwsHeaders): JwsHeaders

    public companion object {
        public val Empty: JwsHeaders = TODO()
    }
}

public sealed interface JwsHeadersBuilder : JwsHeaders, JoseHeadersBuilder {
    override val protected: JwsHeaderBuilder
    override val unprotected: JwsHeaderBuilder
}

// TODO: JwsHeaders vs buildJwsHeaders
public inline fun JwsHeaders(builderAction: JwsHeadersBuilder.() -> Unit): JwsHeaders = TODO()

// algorithm will be used for protected header
public inline fun JwsHeaders(
    algorithm: JwsAlgorithm,
    builderAction: JwsHeadersBuilder.() -> Unit,
): JwsHeaders = TODO()
