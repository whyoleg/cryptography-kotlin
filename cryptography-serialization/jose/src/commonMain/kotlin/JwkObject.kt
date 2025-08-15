/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@Serializable(JwkObjectSerializer::class)
public class JwkObject(
    public val parameters: JwkParameters,
    public val keyId: String? = null,
    public val algorithm: JwaAlgorithm? = null,
    public val publicKeyUse: JwkPublicKeyUse? = null,
    public val keyOperations: List<JwkOperation> = emptyList(),
    public val x509Url: String? = null,
    public val x509CertificateChain: List<ByteArray> = emptyList(),
    public val x509CertificateSha1Thumbprint: ByteArray? = null,
    public val x509CertificateSha256Thumbprint: ByteArray? = null,
) {
    // thumbprint

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwkObject

        if (parameters != other.parameters) return false
        if (publicKeyUse != other.publicKeyUse) return false
        if (keyOperations != other.keyOperations) return false
        if (algorithm != other.algorithm) return false
        if (keyId != other.keyId) return false
        if (x509Url != other.x509Url) return false
        if (x509CertificateChain != other.x509CertificateChain) return false
        if (!x509CertificateSha1Thumbprint.contentEquals(other.x509CertificateSha1Thumbprint)) return false
        if (!x509CertificateSha256Thumbprint.contentEquals(other.x509CertificateSha256Thumbprint)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = parameters.hashCode()
        result = 31 * result + (publicKeyUse?.hashCode() ?: 0)
        result = 31 * result + keyOperations.hashCode()
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (x509Url?.hashCode() ?: 0)
        result = 31 * result + x509CertificateChain.hashCode()
        result = 31 * result + (x509CertificateSha1Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (x509CertificateSha256Thumbprint?.contentHashCode() ?: 0)
        return result
    }

    // TODO: toString
}

@Serializable
public class JwkSet(public val keys: List<JwkObject>) {
    init {
        require(keys.isNotEmpty()) { "JwkSet must contain at least one key" }
    }
}

// TODO: should allow contextual serialization for algorithm and parameters
internal object JwkObjectSerializer : KSerializer<JwkObject> {
    override val descriptor: SerialDescriptor
        get() = TODO("Not yet implemented")

    override fun serialize(encoder: Encoder, value: JwkObject) {
        TODO("Not yet implemented")
    }

    override fun deserialize(decoder: Decoder): JwkObject {
        TODO("Not yet implemented")
    }
}
