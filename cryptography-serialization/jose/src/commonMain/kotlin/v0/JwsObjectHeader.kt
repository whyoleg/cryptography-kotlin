/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JwsObjectHeader : JwsHeader {
    public val protected: JwsHeader
    public val unprotected: JwsHeader
}

public sealed interface JwsObjectHeaderBuilder : JwsObjectHeader {
    override val protected: JwsHeaderBuilder
    override val unprotected: JwsHeaderBuilder

    public fun fromObjectHeader(header: JwsObjectHeader)
}

public inline fun JwsObjectHeaderBuilder.protected(builderAction: JwsHeaderBuilder.() -> Unit) {
    protected.apply(builderAction)
}

public inline fun JwsObjectHeaderBuilder.unprotected(builderAction: JwsHeaderBuilder.() -> Unit) {
    unprotected.apply(builderAction)
}

public inline fun jwsObjectHeader(builderAction: JwsObjectHeaderBuilder.() -> Unit): JwsObjectHeader = TODO()

// algorithm will be used for protected header
public inline fun jwsObjectHeader(
    algorithm: JwsHeader.Algorithm,
    builderAction: JwsObjectHeaderBuilder.() -> Unit,
): JwsObjectHeader = TODO()
