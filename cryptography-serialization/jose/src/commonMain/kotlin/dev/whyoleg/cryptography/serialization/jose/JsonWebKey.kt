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
    /** Additional key-specific parameters */
    val additionalParameters: Map<String, JsonElement> = emptyMap()
)

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
}