/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public class JsonWebKey(
    public val type: Type,
    public val use: Use? = null,
    public val operations: Set<Operation> = emptySet(),
    public val id: String? = null,
    public val x509: X509CertificateData? = null,
) {
    public class X509CertificateData(
        public val url: String? = null, // URI
        public val certificateChain: List<ByteArray> = emptyList(),
        public val certificateSha1Thumbprint: ByteArray? = null,
        public val certificateSha256Thumbprint: ByteArray? = null,
    )

    public interface Parameters {
        public fun thumbprintingInput(): ByteArray
    }

    public interface RsaParameters {
        // BigInt
        public val modulus: ByteArray
        public val exponent: ByteArray

        public val privateExponent: ByteArray

    }

    public interface EcParameters {
        public val curve: String
        public val x: ByteArray
        public val y: ByteArray // TODO: nullable?

        public val d: ByteArray? // if present -> public key
    }

    public interface OctetKeyPairParameters {
        public val curve: String
        public val x: ByteArray
        public val d: ByteArray?
    }
//
///**
// * JSON Web Key (JWK) as defined in RFC 7517.
// *
// * A JWK is a JSON object that represents a cryptographic key.
// * This is a sealed interface that provides type-safe access to different key types.
// */
//@Serializable(with = JsonWebKeySerializer::class)
//public sealed interface JsonWebKey {
//    /** Key Type - identifies the cryptographic algorithm family used with the key */
//    val keyType: JwkKeyType
//    /** Public Key Use - identifies the intended use of the public key */
//    val keyUse: JwkKeyUse?
//    /** Key Operations - identifies the operation(s) for which the key is intended to be used */
//    val keyOperations: List<JwkKeyOperation>?
//    /** Algorithm - identifies the algorithm intended for use with the key */
//    val algorithm: JwsAlgorithm?
//    /** Key ID - used to match a specific key among multiple keys */
//    val keyId: String?
//    /** X.509 URL - URI that refers to a resource for an X.509 public key certificate or certificate chain */
//    val x509Url: String?
//    /** X.509 Certificate Chain - chain of one or more PKIX certificates */
//    val x509CertificateChain: List<String>?
//    /** X.509 Certificate SHA-1 Thumbprint */
//    val x509CertificateSha1Thumbprint: String?
//    /** X.509 Certificate SHA-256 Thumbprint */
//    val x509CertificateSha256Thumbprint: String?
//    /** Additional key-specific parameters */
//    val additionalParameters: Map<String, JsonElement>
//}

    public /*value*/ class Type(public val value: String) {
        public companion object {
            public val RSA: Type = Type("RSA")
            public val EC: Type = Type("EC")
            public val OctetSequence: Type = Type("oct")
            public val OctetKeyPair: Type = Type("OKP")
        }
    }

    public /*value*/ class Use(public val value: String) {
        public companion object {
            public val Signature: Use = Use("sig")
            public val Encryption: Use = Use("enc")
        }
    }

    public /*value*/ class Operation(public val value: String) {
        public companion object {
            public val Sign: Operation = Operation("sign")
            public val Verify: Operation = Operation("verify")
        }
    }
}

public class JsonWebKeySet(
    public val keys: List<JsonWebKey>,
)

///**
// * Key Operations
// */
//@Serializable
//@JvmInline
//public value class JwkKeyOperation(public val value: String) {
//    public companion object {
//        /** Sign Operation */
//        public val SIGN: JwkKeyOperation = JwkKeyOperation("sign")
//        /** Verify Operation */
//        public val VERIFY: JwkKeyOperation = JwkKeyOperation("verify")
//        /** Encrypt Operation */
//        public val ENCRYPT: JwkKeyOperation = JwkKeyOperation("encrypt")
//        /** Decrypt Operation */
//        public val DECRYPT: JwkKeyOperation = JwkKeyOperation("decrypt")
//        /** Wrap Key Operation */
//        public val WRAP_KEY: JwkKeyOperation = JwkKeyOperation("wrapKey")
//        /** Unwrap Key Operation */
//        public val UNWRAP_KEY: JwkKeyOperation = JwkKeyOperation("unwrapKey")
//        /** Derive Key Operation */
//        public val DERIVE_KEY: JwkKeyOperation = JwkKeyOperation("deriveKey")
//        /** Derive Bits Operation */
//        public val DERIVE_BITS: JwkKeyOperation = JwkKeyOperation("deriveBits")
//    }
//}
//
