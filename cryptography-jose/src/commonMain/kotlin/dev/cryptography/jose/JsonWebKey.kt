/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.cryptography.jose

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * JSON Web Key (JWK) as defined in RFC 7517.
 * 
 * A JWK is a JSON object that represents a cryptographic key.
 */
@Serializable
public data class JsonWebKey(
    /** Key Type - identifies the cryptographic algorithm family used with the key */
    val kty: String,
    /** Public Key Use - identifies the intended use of the public key */
    val use: String? = null,
    /** Key Operations - identifies the operation(s) for which the key is intended to be used */
    val key_ops: List<String>? = null,
    /** Algorithm - identifies the algorithm intended for use with the key */
    val alg: String? = null,
    /** Key ID - used to match a specific key among multiple keys */
    val kid: String? = null,
    /** X.509 URL - URI that refers to a resource for an X.509 public key certificate or certificate chain */
    val x5u: String? = null,
    /** X.509 Certificate Chain - chain of one or more PKIX certificates */
    val x5c: List<String>? = null,
    /** X.509 Certificate SHA-1 Thumbprint */
    val x5t: String? = null,
    /** X.509 Certificate SHA-256 Thumbprint */
    @Serializable(with = kotlinx.serialization.json.JsonElementSerializer::class)
    val x5t_S256: JsonElement? = null,
    /** Additional key-specific parameters */
    val additionalParameters: Map<String, JsonElement> = emptyMap()
) {
    companion object {
        // Key Types as defined in RFC 7518
        public const val KEY_TYPE_RSA: String = "RSA"
        public const val KEY_TYPE_EC: String = "EC"
        public const val KEY_TYPE_SYMMETRIC: String = "oct"
        
        // Public Key Use values
        public const val USE_SIGNATURE: String = "sig"
        public const val USE_ENCRYPTION: String = "enc"
        
        // Key Operations
        public const val OP_SIGN: String = "sign"
        public const val OP_VERIFY: String = "verify"
        public const val OP_ENCRYPT: String = "encrypt"
        public const val OP_DECRYPT: String = "decrypt"
        public const val OP_WRAP_KEY: String = "wrapKey"
        public const val OP_UNWRAP_KEY: String = "unwrapKey"
        public const val OP_DERIVE_KEY: String = "deriveKey"
        public const val OP_DERIVE_BITS: String = "deriveBits"
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
    public fun findByKeyId(kid: String): JsonWebKey? = keys.find { it.kid == kid }
    
    /**
     * Finds keys by their intended use.
     */
    public fun findByUse(use: String): List<JsonWebKey> = keys.filter { it.use == use }
    
    /**
     * Finds keys by their algorithm.
     */
    public fun findByAlgorithm(alg: String): List<JsonWebKey> = keys.filter { it.alg == alg }
}