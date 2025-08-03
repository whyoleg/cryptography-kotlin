/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public class JwsAlgorithm(public val value: String) {
    public companion object {
        public val HS256: JwsAlgorithm = JwsAlgorithm("HS256")
    }
}

public sealed interface JwsHeader : JoseHeader {
    public val algorithm: JwsAlgorithm

    public operator fun plus(other: JwsHeader): JwsHeader

    public companion object {
        public val Empty: JwsHeader = TODO()
    }
}

public sealed interface JwsHeaderBuilder : JoseHeaderBuilder, JwsHeader {
    public override var algorithm: JwsAlgorithm

    public fun fromHeader(header: JwsHeader)
}

public inline fun jwsHeader(builderAction: JwsHeaderBuilder.() -> Unit): JwsHeader = TODO()

public inline fun jwsHeader(
    algorithm: JwsAlgorithm,
    builderAction: JwsHeaderBuilder.() -> Unit,
): JwsHeader = TODO()
