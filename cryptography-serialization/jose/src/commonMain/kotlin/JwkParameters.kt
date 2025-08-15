/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:UseSerializers(
    BigIntAsBase64UrlSerializer::class,
    ByteArrayAsBase64UrlSerializer::class
)

package dev.whyoleg.cryptography.serialization.jose

import dev.whyoleg.cryptography.bigint.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.jvm.*

@Serializable
@JvmInline
public value class JwkType(public val name: String) {
    public companion object {
        public val RSA: JwkType = JwkType("RSA")
        public val EC: JwkType = JwkType("EC")
        public val OctetKeyPair: JwkType = JwkType("OKP")
        public val OctetSequence: JwkType = JwkType("oct")
    }
}

@Serializable
@JvmInline
public value class JwkPublicKeyUse(public val name: String) {
    public companion object {
        public val Signature: JwkPublicKeyUse = JwkPublicKeyUse("sig")
        public val Encryption: JwkPublicKeyUse = JwkPublicKeyUse("enc")
    }
}

@Serializable
@JvmInline
public value class JwkOperation(public val name: String) {
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
@JvmInline
public value class JwkEllipticCurve(public val name: String) {
    public companion object {
        public val P256: JwkEllipticCurve = JwkEllipticCurve("P-256")
        public val P384: JwkEllipticCurve = JwkEllipticCurve("P-384")
        public val P521: JwkEllipticCurve = JwkEllipticCurve("P-521")

        public val secp256k1: JwkEllipticCurve = JwkEllipticCurve("secp256k1")

        public val Ed25519: JwkEllipticCurve = JwkEllipticCurve("Ed25519")
        public val Ed448: JwkEllipticCurve = JwkEllipticCurve("Ed448")
    }
}

@Serializable(JwkParametersSerializer::class)
public interface JwkParameters {
    // type is encoded/decoded only when serializing JwkParameters - similar to polymorphic serialization
    public val type: JwkType

    // thumbprint

    @Serializable
    public class RSA(
        @SerialName("n")
        public val modulus: BigInt,
        @SerialName("e")
        public val exponent: BigInt,
        @SerialName("d")
        public val privateExponent: BigInt? = null,

        @SerialName("p")
        public val firstPrimeFactor: BigInt? = null,
        @SerialName("q")
        public val secondPrimeFactor: BigInt? = null,
        @SerialName("dp")
        public val firstFactorCrtExponent: BigInt? = null,
        @SerialName("dq")
        public val secondFactorCrtExponent: BigInt? = null,
        @SerialName("qi")
        public val firstCrtCoefficient: BigInt? = null,
        @SerialName("oth")
        public val otherPrimes: List<PrimeInfo> = emptyList(),
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.RSA

        @Serializable
        public class PrimeInfo(
            @SerialName("r")
            public val primeFactor: BigInt,
            @SerialName("d")
            public val factorCrtExponent: BigInt,
            @SerialName("t")
            public val factorCrtCoefficient: BigInt,
        )
    }

    @Serializable
    public class EC(
        @SerialName("crv")
        public val curve: JwkEllipticCurve,
        @SerialName("x")
        public val xCoordinate: ByteArray,
        @SerialName("y")
        public val yCoordinate: ByteArray,
        @SerialName("d")
        public val privateKey: ByteArray? = null,
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.EC
    }

    @Serializable
    public class OctetSequence(
        @SerialName("k")
        public val secret: ByteArray,
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.OctetSequence
    }

    @Serializable
    public class OctetKeyPair(
        @SerialName("crv")
        public val curve: JwkEllipticCurve,
        @SerialName("x")
        public val publicKey: ByteArray,
        @SerialName("d")
        public val privateKey: ByteArray? = null,
    ) : JwkParameters {
        override val type: JwkType get() = JwkType.OctetKeyPair
    }
}

internal object JwkParametersSerializer : KSerializer<JwkParameters> {
    override val descriptor: SerialDescriptor = PolymorphicSerializer(JwkParameters::class).descriptor

    override fun serialize(encoder: Encoder, value: JwkParameters) {
        TODO("Not yet implemented")
    }

    override fun deserialize(decoder: Decoder): JwkParameters {
        TODO("Not yet implemented")
    }
}

internal object BigIntAsBase64UrlSerializer : KSerializer<BigInt> {
    override val descriptor: SerialDescriptor
        get() = TODO("Not yet implemented")

    override fun serialize(encoder: Encoder, value: BigInt) {
        TODO("Not yet implemented")
    }

    override fun deserialize(decoder: Decoder): BigInt {
        TODO("Not yet implemented")
    }
}

internal object ByteArrayAsBase64UrlSerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor
        get() = TODO("Not yet implemented")

    override fun serialize(encoder: Encoder, value: ByteArray) {
        TODO("Not yet implemented")
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        TODO("Not yet implemented")
    }
}
