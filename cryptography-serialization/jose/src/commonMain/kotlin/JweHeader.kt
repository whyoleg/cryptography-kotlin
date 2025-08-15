/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*

@Serializable
public sealed interface JweHeader : JoseHeader {
    public val algorithm: JweAlgorithm?
    public val encryptionAlgorithm: JweEncryptionAlgorithm // enc

    public val compressionAlgorithm: JweCompressionAlgorithm? // zip

    // ECDH-ES key agreement parameters
    public val ephemeralPublicKey: JwkObject? // epk
    public val agreementPartyUInfo: ByteArray? // apu
    public val agreementPartyVInfo: ByteArray? // apv

    // AES GCM (A___GCMKW)
    public val initializationVector: ByteArray? // iv
    public val authenticationTag: ByteArray? // tag

    // PBES2 key encryption parameters
    public val pbes2SaltInput: ByteArray? // p2s
    public val pbes2Count: Long? // p2c

    public operator fun plus(other: JweHeader): JweHeader

    public companion object {
        public val Empty: JweHeader = TODO()
    }
}

public sealed interface JweHeaderBuilder : JoseHeaderBuilder, JweHeader {
    public override var algorithm: JweAlgorithm?
    public override var encryptionAlgorithm: JweEncryptionAlgorithm

    public override var compressionAlgorithm: JweCompressionAlgorithm?

    public override var ephemeralPublicKey: JwkObject?
    public override var agreementPartyUInfo: ByteArray?
    public override var agreementPartyVInfo: ByteArray?

    public override var initializationVector: ByteArray?
    public override var authenticationTag: ByteArray?

    public override var pbes2SaltInput: ByteArray?
    public override var pbes2Count: Long?
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
