/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JwsHeader : JoseHeader {
    override val algorithm: Algorithm

    public operator fun plus(other: JwsHeader): JwsHeader

    public class Algorithm(override val value: String) : JoseHeader.Algorithm {
        public companion object : JoseHeader.ParameterKey<String> by JoseHeader.ParameterKey.of("alg") {
            public val HS256: Algorithm = Algorithm("HS256")
        }
    }

    public companion object {
        public val Empty: JwsHeader = TODO()
    }
}

public sealed interface JwsHeaderBuilder : JoseHeaderBuilder, JwsHeader {
    public override var algorithm: JwsHeader.Algorithm

    public fun fromHeader(header: JwsHeader)
}

public inline fun jwsHeader(builderAction: JwsHeaderBuilder.() -> Unit): JwsHeader = TODO()

public inline fun jwsHeader(
    algorithm: JwsHeader.Algorithm,
    builderAction: JwsHeaderBuilder.() -> Unit,
): JwsHeader = TODO()
