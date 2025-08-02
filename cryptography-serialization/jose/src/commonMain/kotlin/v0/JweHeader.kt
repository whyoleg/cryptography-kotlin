/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public sealed interface JweHeader : JoseHeader {
    override val algorithm: Algorithm
    public val encryptionAlgorithm: EncryptionAlgorithm

    public operator fun plus(other: JweHeader): JweHeader

    public class Algorithm(override val value: String) : JoseHeader.Algorithm {
        public companion object : JoseHeader.ParameterKey<Algorithm> by JoseHeader.ParameterKey.of("alg") {
            // public val HS256: Algorithm = Algorithm("HS256")
        }
    }

    public class EncryptionAlgorithm(public val value: String) {
        public companion object : JoseHeader.ParameterKey<EncryptionAlgorithm> by JoseHeader.ParameterKey.of("enc") {
            // public val HS256: Algorithm = Algorithm("HS256")
        }
    }

    public companion object {
        public val Empty: JweHeader = TODO()
    }
}

public sealed interface JweHeaderBuilder : JoseHeaderBuilder, JweHeader {
    public override var algorithm: JweHeader.Algorithm
    public override var encryptionAlgorithm: JweHeader.EncryptionAlgorithm

    public fun fromHeader(header: JweHeader)
}

public inline fun jweHeader(builderAction: JweHeaderBuilder.() -> Unit): JweHeader = TODO()

public inline fun jweHeader(
    algorithm: JweHeader.Algorithm,
    encryptionAlgorithm: JweHeader.EncryptionAlgorithm,
    builderAction: JweHeaderBuilder.() -> Unit,
): JweHeader = TODO()
