/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import dev.whyoleg.cryptography.serialization.jose.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.json.*
import kotlin.jvm.*

// TODO: toString
// TODO: custom serializer
@Serializable // json only?
public data class JwkObject(
    public val parameters: JwkParameters,
    public val publicKeyUse: JwkPublicKeyUse? = null,
    public val keyOperations: List<JwkOperation> = emptyList(),
    @Contextual
    public val algorithm: JwaAlgorithm? = null, // TODO????????
    public val keyId: String? = null,
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
}

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

// TODO: should those be value class at all?
@Serializable
@JvmInline
public value class JwkType(public val value: String) {
    public companion object {
        public val RSA: JwkType = JwkType("RSA")
        public val EC: JwkType = JwkType("EC")
        public val OctetKeyPair: JwkType = JwkType("OKP")
        public val OctetSequence: JwkType = JwkType("oct")
    }
}

@Serializable
@JvmInline
public value class JwkPublicKeyUse(public val value: String) {
    public companion object {
        public val Signature: JwkPublicKeyUse = JwkPublicKeyUse("sig")
        public val Encryption: JwkPublicKeyUse = JwkPublicKeyUse("enc")
    }
}

@Serializable
@JvmInline
public value class JwkOperation(public val value: String) {
    public companion object {
        public val Sign: JwkOperation = JwkOperation("sign")
        public val Verify: JwkOperation = JwkOperation("verify")
        public val Encrypt: JwkOperation = JwkOperation("encrypt")
        public val Decrypt: JwkOperation = JwkOperation("decrypt")
        public val WrapKey: JwkOperation = JwkOperation("wrapKey")
        public val UnwrapKey: JwkOperation = JwkOperation("unwrapKey")
        public val DeriveKey: JwkOperation = JwkOperation("deriveKey")
        public val DeriveBits: JwkOperation = JwkOperation("deriveBits")
    }
}

@Serializable
public sealed interface JwkParameters {
    public val type: JwkType

    // public val hasPrivateKey: Boolean
    // thumbprint

    @Serializable
    public data class RSA(
        // BigInt
        public val modulus: ByteArray,
        public val exponent: ByteArray,
        public val privateExponent: ByteArray?,
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.RSA
    }

    public data class EC(
        public val curve: String,
        public val x: ByteArray,
        public val y: ByteArray, // TODO: nullable?
        public val d: ByteArray?, // if present -> private key
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.EC
    }

    public data class OctetSequence(
        public val k: ByteArray,
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.OctetSequence
    }

    public data class OctetKeyPair(
        public val curve: String,
        public val x: ByteArray,
        public val d: ByteArray?,
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.OctetKeyPair
    }

    public data class Unknown(
        override val type: JwkType,
        public val properties: JsonObject,
    ) : JwkParameters
}

@Serializable
public class JwkSet(public val keys: List<JwkObject>) {
    init {
        require(keys.isNotEmpty()) { "JwkSet must contain at least one key" }
    }
}

private fun test() {
//    Json(Json.JoseCompliant) {
//        serializersModule = SerializersModule {
//            contextual(JwaAlgorithm::class, JwaAlgorithmSerializer)
//            contextual(JwkParameters::class, TODO())
//        }
//    }


    JwkObject.decodeFromString("").encodeToString()

    jwkRsaKey(

    )



    jwkRsaParameters()
    jwkObject(
        //use, operations, kid, etc
        JwkParameters.rsa()
        // rsaParameters(modulus, exponent)
    )

    JsonWebKey.RSA(
        modulus = byteArrayOf(),
        exponent = byteArrayOf(),
        JsonWebKey.Use.Signature,
        listof(JsonWebKey.Operation.Sign),
        ""
    )

    JsonWebKey(
        JsonWebKey.Parameters.RSA(
            modulus = byteArrayOf(),
            exponent = byteArrayOf()
        ),
        JsonWebKey.Use.Signature,
        listof(JsonWebKey.Operation.Sign),
        ""
    )

    JwkObject(
        parameters = JwkParameters.RSA(
            modulus = byteArrayOf(),
            exponent = byteArrayOf(),
            null
        ),
        keyId = "test-key-id",
        publicKeyUse = JwkPublicKeyUse.Signature,
        keyOperations = listOf(JwkOperation.Sign),
        algorithm = null // ???
    )
}
