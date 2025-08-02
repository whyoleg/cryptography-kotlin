/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JwsCompositeHeader : JoseCompositeHeader {
    override val protected: JwsHeader
    override val unprotected: JwsHeader

    override val combined: JwsHeader
}

public sealed interface JwsCompositeHeaderBuilder : JwsCompositeHeader, JoseCompositeHeaderBuilder {
    override val protected: JwsHeaderBuilder
    override val unprotected: JwsHeaderBuilder

    public fun fromCompositeHeader(header: JwsCompositeHeader)
}

public inline fun jwsCompositeHeader(builderAction: JwsCompositeHeaderBuilder.() -> Unit): JwsCompositeHeader = TODO()

// algorithm will be used for protected header
public inline fun jwsCompositeHeader(
    algorithm: JwsHeader.Algorithm,
    builderAction: JwsCompositeHeaderBuilder.() -> Unit,
): JwsCompositeHeader = TODO()
