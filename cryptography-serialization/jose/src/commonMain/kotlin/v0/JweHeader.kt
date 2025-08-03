/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// alg
public class JweKeyManagementAlgorithm(public val value: String) {
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
    public val algorithm: JweKeyManagementAlgorithm
    public val encryptionAlgorithm: JweContentEncryptionAlgorithm

    public operator fun plus(other: JweHeader): JweHeader

    public companion object {
        public val Empty: JweHeader = TODO()
    }
}

public sealed interface JweHeaderBuilder : JoseHeaderBuilder, JweHeader {
    public override var algorithm: JweKeyManagementAlgorithm
    public override var encryptionAlgorithm: JweContentEncryptionAlgorithm

    public fun fromHeader(header: JweHeader)
}

public inline fun jweHeader(builderAction: JweHeaderBuilder.() -> Unit): JweHeader = TODO()

public inline fun jweHeader(
    algorithm: JweKeyManagementAlgorithm,
    encryptionAlgorithm: JweContentEncryptionAlgorithm,
    builderAction: JweHeaderBuilder.() -> Unit,
): JweHeader = TODO()
