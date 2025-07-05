/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlin.jvm.JvmInline

/**
 * Key Types as defined in RFC 7518
 */
@Serializable
@JvmInline
public value class JwkKeyType(public val value: String) {
    public companion object {
        /** RSA Key Type */
        public val RSA: JwkKeyType = JwkKeyType("RSA")
        /** Elliptic Curve Key Type */
        public val EC: JwkKeyType = JwkKeyType("EC")
        /** Symmetric Key Type */
        public val SYMMETRIC: JwkKeyType = JwkKeyType("oct")
    }
}

/**
 * Public Key Use values
 */
@Serializable
@JvmInline
public value class JwkKeyUse(public val value: String) {
    public companion object {
        /** Signature Use */
        public val SIGNATURE: JwkKeyUse = JwkKeyUse("sig")
        /** Encryption Use */
        public val ENCRYPTION: JwkKeyUse = JwkKeyUse("enc")
    }
}

/**
 * Key Operations
 */
@Serializable
@JvmInline
public value class JwkKeyOperation(public val value: String) {
    public companion object {
        /** Sign Operation */
        public val SIGN: JwkKeyOperation = JwkKeyOperation("sign")
        /** Verify Operation */
        public val VERIFY: JwkKeyOperation = JwkKeyOperation("verify")
        /** Encrypt Operation */
        public val ENCRYPT: JwkKeyOperation = JwkKeyOperation("encrypt")
        /** Decrypt Operation */
        public val DECRYPT: JwkKeyOperation = JwkKeyOperation("decrypt")
        /** Wrap Key Operation */
        public val WRAP_KEY: JwkKeyOperation = JwkKeyOperation("wrapKey")
        /** Unwrap Key Operation */
        public val UNWRAP_KEY: JwkKeyOperation = JwkKeyOperation("unwrapKey")
        /** Derive Key Operation */
        public val DERIVE_KEY: JwkKeyOperation = JwkKeyOperation("deriveKey")
        /** Derive Bits Operation */
        public val DERIVE_BITS: JwkKeyOperation = JwkKeyOperation("deriveBits")
    }
}

/**
 * Elliptic Curve identifiers
 */
@Serializable
@JvmInline
public value class JwkEllipticCurve(public val value: String) {
    public companion object {
        /** P-256 curve */
        public val P256: JwkEllipticCurve = JwkEllipticCurve("P-256")
        /** P-384 curve */
        public val P384: JwkEllipticCurve = JwkEllipticCurve("P-384")
        /** P-521 curve */
        public val P521: JwkEllipticCurve = JwkEllipticCurve("P-521")
    }
}

/**
 * JSON Web Key (JWK) as defined in RFC 7517.
 * 
 * A JWK is a JSON object that represents a cryptographic key.
 */
@Serializable
public data class JsonWebKey(
    /** Key Type - identifies the cryptographic algorithm family used with the key */
    @SerialName("kty")
    val keyType: JwkKeyType,
    /** Public Key Use - identifies the intended use of the public key */
    @SerialName("use")
    val keyUse: JwkKeyUse? = null,
    /** Key Operations - identifies the operation(s) for which the key is intended to be used */
    @SerialName("key_ops")
    val keyOperations: List<JwkKeyOperation>? = null,
    /** Algorithm - identifies the algorithm intended for use with the key */
    @SerialName("alg")
    val algorithm: JwsAlgorithm? = null,
    /** Key ID - used to match a specific key among multiple keys */
    @SerialName("kid")
    val keyId: String? = null,
    /** X.509 URL - URI that refers to a resource for an X.509 public key certificate or certificate chain */
    @SerialName("x5u")
    val x509Url: String? = null,
    /** X.509 Certificate Chain - chain of one or more PKIX certificates */
    @SerialName("x5c")
    val x509CertificateChain: List<String>? = null,
    /** X.509 Certificate SHA-1 Thumbprint */
    @SerialName("x5t")
    val x509CertificateSha1Thumbprint: String? = null,
    /** X.509 Certificate SHA-256 Thumbprint */
    @SerialName("x5t#S256")
    val x509CertificateSha256Thumbprint: String? = null,
    
    // RSA Key Parameters (RFC 7518 Section 6.3)
    /** Modulus (for RSA keys) */
    @SerialName("n")
    val modulus: String? = null,
    /** Exponent (for RSA keys) */
    @SerialName("e")
    val exponent: String? = null,
    /** Private Exponent (for RSA private keys) or ECC Private Key (for EC private keys) */
    @SerialName("d")
    val privateKey: String? = null,
    /** First Prime Factor (for RSA private keys) */
    @SerialName("p")
    val firstPrimeFactor: String? = null,
    /** Second Prime Factor (for RSA private keys) */
    @SerialName("q")
    val secondPrimeFactor: String? = null,
    /** First Factor CRT Exponent (for RSA private keys) */
    @SerialName("dp")
    val firstFactorCrtExponent: String? = null,
    /** Second Factor CRT Exponent (for RSA private keys) */
    @SerialName("dq")
    val secondFactorCrtExponent: String? = null,
    /** First CRT Coefficient (for RSA private keys) */
    @SerialName("qi")
    val firstCrtCoefficient: String? = null,
    
    // Elliptic Curve Key Parameters (RFC 7518 Section 6.2)
    /** Curve (for EC keys) */
    @SerialName("crv")
    val curve: JwkEllipticCurve? = null,
    /** X Coordinate (for EC keys) */
    @SerialName("x")
    val xCoordinate: String? = null,
    /** Y Coordinate (for EC keys) */
    @SerialName("y")
    val yCoordinate: String? = null,
    
    // Symmetric Key Parameters (RFC 7518 Section 6.4)
    /** Key Value (for symmetric keys) */
    @SerialName("k")
    val keyValue: String? = null,
    
    /** Additional key-specific parameters */
    val additionalParameters: Map<String, JsonElement> = emptyMap()
) {
    
    /**
     * Determines if this is a private key based on the presence of private key parameters.
     */
    val isPrivateKey: Boolean
        get() = when (keyType) {
            JwkKeyType.RSA -> privateKey != null
            JwkKeyType.EC -> privateKey != null
            JwkKeyType.SYMMETRIC -> keyValue != null
            else -> false
        }
    
    /**
     * Determines if this is a public key (not private and has public key parameters).
     */
    val isPublicKey: Boolean
        get() = when (keyType) {
            JwkKeyType.RSA -> modulus != null && exponent != null && privateKey == null
            JwkKeyType.EC -> curve != null && xCoordinate != null && yCoordinate != null && privateKey == null
            JwkKeyType.SYMMETRIC -> false // Symmetric keys are neither public nor private in the traditional sense
            else -> false
        }
}

/**
 * JSON Web Key Set (JWK Set) as defined in RFC 7517.
 * 
 * A JWK Set is a JSON object that represents a set of JWKs.
 */
@Serializable
public data class JsonWebKeySet(
    /** Array of JWK values */
    val keys: List<JsonWebKey>
) {
    /**
     * Finds a key by its Key ID (kid).
     */
    public fun findByKeyId(keyId: String): JsonWebKey? = keys.find { it.keyId == keyId }
    
    /**
     * Finds keys by their intended use.
     */
    public fun findByUse(keyUse: JwkKeyUse): List<JsonWebKey> = keys.filter { it.keyUse == keyUse }
    
    /**
     * Finds keys by their algorithm.
     */
    public fun findByAlgorithm(algorithm: JwsAlgorithm): List<JsonWebKey> = keys.filter { it.algorithm == algorithm }
    
    /**
     * Finds keys by their key type.
     */
    public fun findByKeyType(keyType: JwkKeyType): List<JsonWebKey> = keys.filter { it.keyType == keyType }
    
    /**
     * Finds all public keys in the set.
     */
    public fun findPublicKeys(): List<JsonWebKey> = keys.filter { it.isPublicKey }
    
    /**
     * Finds all private keys in the set.
     */
    public fun findPrivateKeys(): List<JsonWebKey> = keys.filter { it.isPrivateKey }
}