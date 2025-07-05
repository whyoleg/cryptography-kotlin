/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.json.*
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
 * This is a sealed interface that provides type-safe access to different key types.
 */
@Serializable(with = JsonWebKeySerializer::class)
public sealed interface JsonWebKey {
    /** Key Type - identifies the cryptographic algorithm family used with the key */
    val keyType: JwkKeyType
    /** Public Key Use - identifies the intended use of the public key */
    val keyUse: JwkKeyUse?
    /** Key Operations - identifies the operation(s) for which the key is intended to be used */
    val keyOperations: List<JwkKeyOperation>?
    /** Algorithm - identifies the algorithm intended for use with the key */
    val algorithm: JwsAlgorithm?
    /** Key ID - used to match a specific key among multiple keys */
    val keyId: String?
    /** X.509 URL - URI that refers to a resource for an X.509 public key certificate or certificate chain */
    val x509Url: String?
    /** X.509 Certificate Chain - chain of one or more PKIX certificates */
    val x509CertificateChain: List<String>?
    /** X.509 Certificate SHA-1 Thumbprint */
    val x509CertificateSha1Thumbprint: String?
    /** X.509 Certificate SHA-256 Thumbprint */
    val x509CertificateSha256Thumbprint: String?
    /** Additional key-specific parameters */
    val additionalParameters: Map<String, JsonElement>
}

/**
 * RSA JSON Web Key base interface.
 */
public sealed interface RsaJsonWebKey : JsonWebKey {
    override val keyType: JwkKeyType get() = JwkKeyType.RSA
    /** Modulus */
    val modulus: String
    /** Exponent */
    val exponent: String
}

/**
 * RSA Public JSON Web Key.
 */
@Serializable
public data class RsaPublicJsonWebKey(
    override val modulus: String,
    override val exponent: String,
    override val keyUse: JwkKeyUse? = null,
    override val keyOperations: List<JwkKeyOperation>? = null,
    override val algorithm: JwsAlgorithm? = null,
    override val keyId: String? = null,
    override val x509Url: String? = null,
    override val x509CertificateChain: List<String>? = null,
    override val x509CertificateSha1Thumbprint: String? = null,
    override val x509CertificateSha256Thumbprint: String? = null,
    override val additionalParameters: Map<String, JsonElement> = emptyMap()
) : RsaJsonWebKey

/**
 * RSA Private JSON Web Key.
 */
@Serializable
public data class RsaPrivateJsonWebKey(
    override val modulus: String,
    override val exponent: String,
    val privateExponent: String,
    val firstPrimeFactor: String? = null,
    val secondPrimeFactor: String? = null,
    val firstFactorCrtExponent: String? = null,
    val secondFactorCrtExponent: String? = null,
    val firstCrtCoefficient: String? = null,
    override val keyUse: JwkKeyUse? = null,
    override val keyOperations: List<JwkKeyOperation>? = null,
    override val algorithm: JwsAlgorithm? = null,
    override val keyId: String? = null,
    override val x509Url: String? = null,
    override val x509CertificateChain: List<String>? = null,
    override val x509CertificateSha1Thumbprint: String? = null,
    override val x509CertificateSha256Thumbprint: String? = null,
    override val additionalParameters: Map<String, JsonElement> = emptyMap()
) : RsaJsonWebKey

/**
 * Elliptic Curve JSON Web Key base interface.
 */
public sealed interface EcJsonWebKey : JsonWebKey {
    override val keyType: JwkKeyType get() = JwkKeyType.EC
    /** Curve */
    val curve: JwkEllipticCurve
    /** X Coordinate */
    val xCoordinate: String
    /** Y Coordinate */
    val yCoordinate: String
}

/**
 * Elliptic Curve Public JSON Web Key.
 */
@Serializable
public data class EcPublicJsonWebKey(
    override val curve: JwkEllipticCurve,
    override val xCoordinate: String,
    override val yCoordinate: String,
    override val keyUse: JwkKeyUse? = null,
    override val keyOperations: List<JwkKeyOperation>? = null,
    override val algorithm: JwsAlgorithm? = null,
    override val keyId: String? = null,
    override val x509Url: String? = null,
    override val x509CertificateChain: List<String>? = null,
    override val x509CertificateSha1Thumbprint: String? = null,
    override val x509CertificateSha256Thumbprint: String? = null,
    override val additionalParameters: Map<String, JsonElement> = emptyMap()
) : EcJsonWebKey

/**
 * Elliptic Curve Private JSON Web Key.
 */
@Serializable
public data class EcPrivateJsonWebKey(
    override val curve: JwkEllipticCurve,
    override val xCoordinate: String,
    override val yCoordinate: String,
    val privateKey: String,
    override val keyUse: JwkKeyUse? = null,
    override val keyOperations: List<JwkKeyOperation>? = null,
    override val algorithm: JwsAlgorithm? = null,
    override val keyId: String? = null,
    override val x509Url: String? = null,
    override val x509CertificateChain: List<String>? = null,
    override val x509CertificateSha1Thumbprint: String? = null,
    override val x509CertificateSha256Thumbprint: String? = null,
    override val additionalParameters: Map<String, JsonElement> = emptyMap()
) : EcJsonWebKey

/**
 * Symmetric JSON Web Key.
 */
@Serializable
public data class SymmetricJsonWebKey(
    val keyValue: String,
    override val keyUse: JwkKeyUse? = null,
    override val keyOperations: List<JwkKeyOperation>? = null,
    override val algorithm: JwsAlgorithm? = null,
    override val keyId: String? = null,
    override val x509Url: String? = null,
    override val x509CertificateChain: List<String>? = null,
    override val x509CertificateSha1Thumbprint: String? = null,
    override val x509CertificateSha256Thumbprint: String? = null,
    override val additionalParameters: Map<String, JsonElement> = emptyMap()
) : JsonWebKey {
    override val keyType: JwkKeyType get() = JwkKeyType.SYMMETRIC
}

/**
 * Custom serializer for JsonWebKey that handles discrimination based on key type and private key presence.
 */
public object JsonWebKeySerializer : KSerializer<JsonWebKey> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JsonWebKey") {
        element<String>("kty")
        element<String?>("use", isOptional = true)
        element<List<String>?>("key_ops", isOptional = true)
        element<String?>("alg", isOptional = true)
        element<String?>("kid", isOptional = true)
        element<String?>("x5u", isOptional = true)
        element<List<String>?>("x5c", isOptional = true)
        element<String?>("x5t", isOptional = true)
        element<String?>("x5t#S256", isOptional = true)
        // RSA parameters
        element<String?>("n", isOptional = true)
        element<String?>("e", isOptional = true)
        element<String?>("d", isOptional = true)
        element<String?>("p", isOptional = true)
        element<String?>("q", isOptional = true)
        element<String?>("dp", isOptional = true)
        element<String?>("dq", isOptional = true)
        element<String?>("qi", isOptional = true)
        // EC parameters
        element<String?>("crv", isOptional = true)
        element<String?>("x", isOptional = true)
        element<String?>("y", isOptional = true)
        // Symmetric parameter
        element<String?>("k", isOptional = true)
    }

    override fun serialize(encoder: Encoder, value: JsonWebKey) {
        val jsonEncoder = encoder as JsonEncoder
        val element = when (value) {
            is RsaPublicJsonWebKey -> buildJsonObject {
                put("kty", JsonPrimitive("RSA"))
                put("n", JsonPrimitive(value.modulus))
                put("e", JsonPrimitive(value.exponent))
                addCommonFields(value)
            }
            is RsaPrivateJsonWebKey -> buildJsonObject {
                put("kty", JsonPrimitive("RSA"))
                put("n", JsonPrimitive(value.modulus))
                put("e", JsonPrimitive(value.exponent))
                put("d", JsonPrimitive(value.privateExponent))
                value.firstPrimeFactor?.let { put("p", JsonPrimitive(it)) }
                value.secondPrimeFactor?.let { put("q", JsonPrimitive(it)) }
                value.firstFactorCrtExponent?.let { put("dp", JsonPrimitive(it)) }
                value.secondFactorCrtExponent?.let { put("dq", JsonPrimitive(it)) }
                value.firstCrtCoefficient?.let { put("qi", JsonPrimitive(it)) }
                addCommonFields(value)
            }
            is EcPublicJsonWebKey -> buildJsonObject {
                put("kty", JsonPrimitive("EC"))
                put("crv", JsonPrimitive(value.curve.value))
                put("x", JsonPrimitive(value.xCoordinate))
                put("y", JsonPrimitive(value.yCoordinate))
                addCommonFields(value)
            }
            is EcPrivateJsonWebKey -> buildJsonObject {
                put("kty", JsonPrimitive("EC"))
                put("crv", JsonPrimitive(value.curve.value))
                put("x", JsonPrimitive(value.xCoordinate))
                put("y", JsonPrimitive(value.yCoordinate))
                put("d", JsonPrimitive(value.privateKey))
                addCommonFields(value)
            }
            is SymmetricJsonWebKey -> buildJsonObject {
                put("kty", JsonPrimitive("oct"))
                put("k", JsonPrimitive(value.keyValue))
                addCommonFields(value)
            }
            else -> error("Unknown JsonWebKey type: ${value::class}")
        }
        jsonEncoder.encodeJsonElement(element)
    }

    override fun deserialize(decoder: Decoder): JsonWebKey {
        val jsonDecoder = decoder as JsonDecoder
        val element = jsonDecoder.decodeJsonElement().jsonObject
        
        val kty = element["kty"]?.jsonPrimitive?.content ?: error("Missing 'kty' field")
        val keyType = JwkKeyType(kty)
        
        return when (keyType) {
            JwkKeyType.RSA -> {
                val modulus = element["n"]?.jsonPrimitive?.content ?: error("Missing 'n' field for RSA key")
                val exponent = element["e"]?.jsonPrimitive?.content ?: error("Missing 'e' field for RSA key")
                val privateExponent = element["d"]?.jsonPrimitive?.content
                
                if (privateExponent != null) {
                    RsaPrivateJsonWebKey(
                        modulus = modulus,
                        exponent = exponent,
                        privateExponent = privateExponent,
                        firstPrimeFactor = element["p"]?.jsonPrimitive?.content,
                        secondPrimeFactor = element["q"]?.jsonPrimitive?.content,
                        firstFactorCrtExponent = element["dp"]?.jsonPrimitive?.content,
                        secondFactorCrtExponent = element["dq"]?.jsonPrimitive?.content,
                        firstCrtCoefficient = element["qi"]?.jsonPrimitive?.content,
                        keyUse = element["use"]?.jsonPrimitive?.content?.let { JwkKeyUse(it) },
                        keyOperations = element["key_ops"]?.jsonArray?.map { JwkKeyOperation(it.jsonPrimitive.content) },
                        algorithm = element["alg"]?.jsonPrimitive?.content?.let { JwsAlgorithm(it) },
                        keyId = element["kid"]?.jsonPrimitive?.content,
                        x509Url = element["x5u"]?.jsonPrimitive?.content,
                        x509CertificateChain = element["x5c"]?.jsonArray?.map { it.jsonPrimitive.content },
                        x509CertificateSha1Thumbprint = element["x5t"]?.jsonPrimitive?.content,
                        x509CertificateSha256Thumbprint = element["x5t#S256"]?.jsonPrimitive?.content,
                        additionalParameters = element.filterKeys { it !in standardFields }
                    )
                } else {
                    RsaPublicJsonWebKey(
                        modulus = modulus,
                        exponent = exponent,
                        keyUse = element["use"]?.jsonPrimitive?.content?.let { JwkKeyUse(it) },
                        keyOperations = element["key_ops"]?.jsonArray?.map { JwkKeyOperation(it.jsonPrimitive.content) },
                        algorithm = element["alg"]?.jsonPrimitive?.content?.let { JwsAlgorithm(it) },
                        keyId = element["kid"]?.jsonPrimitive?.content,
                        x509Url = element["x5u"]?.jsonPrimitive?.content,
                        x509CertificateChain = element["x5c"]?.jsonArray?.map { it.jsonPrimitive.content },
                        x509CertificateSha1Thumbprint = element["x5t"]?.jsonPrimitive?.content,
                        x509CertificateSha256Thumbprint = element["x5t#S256"]?.jsonPrimitive?.content,
                        additionalParameters = element.filterKeys { it !in standardFields }
                    )
                }
            }
            JwkKeyType.EC -> {
                val curve = element["crv"]?.jsonPrimitive?.content?.let { JwkEllipticCurve(it) } ?: error("Missing 'crv' field for EC key")
                val xCoordinate = element["x"]?.jsonPrimitive?.content ?: error("Missing 'x' field for EC key")
                val yCoordinate = element["y"]?.jsonPrimitive?.content ?: error("Missing 'y' field for EC key")
                val privateKey = element["d"]?.jsonPrimitive?.content
                
                if (privateKey != null) {
                    EcPrivateJsonWebKey(
                        curve = curve,
                        xCoordinate = xCoordinate,
                        yCoordinate = yCoordinate,
                        privateKey = privateKey,
                        keyUse = element["use"]?.jsonPrimitive?.content?.let { JwkKeyUse(it) },
                        keyOperations = element["key_ops"]?.jsonArray?.map { JwkKeyOperation(it.jsonPrimitive.content) },
                        algorithm = element["alg"]?.jsonPrimitive?.content?.let { JwsAlgorithm(it) },
                        keyId = element["kid"]?.jsonPrimitive?.content,
                        x509Url = element["x5u"]?.jsonPrimitive?.content,
                        x509CertificateChain = element["x5c"]?.jsonArray?.map { it.jsonPrimitive.content },
                        x509CertificateSha1Thumbprint = element["x5t"]?.jsonPrimitive?.content,
                        x509CertificateSha256Thumbprint = element["x5t#S256"]?.jsonPrimitive?.content,
                        additionalParameters = element.filterKeys { it !in standardFields }
                    )
                } else {
                    EcPublicJsonWebKey(
                        curve = curve,
                        xCoordinate = xCoordinate,
                        yCoordinate = yCoordinate,
                        keyUse = element["use"]?.jsonPrimitive?.content?.let { JwkKeyUse(it) },
                        keyOperations = element["key_ops"]?.jsonArray?.map { JwkKeyOperation(it.jsonPrimitive.content) },
                        algorithm = element["alg"]?.jsonPrimitive?.content?.let { JwsAlgorithm(it) },
                        keyId = element["kid"]?.jsonPrimitive?.content,
                        x509Url = element["x5u"]?.jsonPrimitive?.content,
                        x509CertificateChain = element["x5c"]?.jsonArray?.map { it.jsonPrimitive.content },
                        x509CertificateSha1Thumbprint = element["x5t"]?.jsonPrimitive?.content,
                        x509CertificateSha256Thumbprint = element["x5t#S256"]?.jsonPrimitive?.content,
                        additionalParameters = element.filterKeys { it !in standardFields }
                    )
                }
            }
            JwkKeyType.SYMMETRIC -> {
                val keyValue = element["k"]?.jsonPrimitive?.content ?: error("Missing 'k' field for symmetric key")
                SymmetricJsonWebKey(
                    keyValue = keyValue,
                    keyUse = element["use"]?.jsonPrimitive?.content?.let { JwkKeyUse(it) },
                    keyOperations = element["key_ops"]?.jsonArray?.map { JwkKeyOperation(it.jsonPrimitive.content) },
                    algorithm = element["alg"]?.jsonPrimitive?.content?.let { JwsAlgorithm(it) },
                    keyId = element["kid"]?.jsonPrimitive?.content,
                    x509Url = element["x5u"]?.jsonPrimitive?.content,
                    x509CertificateChain = element["x5c"]?.jsonArray?.map { it.jsonPrimitive.content },
                    x509CertificateSha1Thumbprint = element["x5t"]?.jsonPrimitive?.content,
                    x509CertificateSha256Thumbprint = element["x5t#S256"]?.jsonPrimitive?.content,
                    additionalParameters = element.filterKeys { it !in standardFields }
                )
            }
            else -> error("Unsupported key type: $kty")
        }
    }
    
    private fun JsonObjectBuilder.addCommonFields(value: JsonWebKey) {
        value.keyUse?.let { put("use", JsonPrimitive(it.value)) }
        value.keyOperations?.let { ops -> put("key_ops", JsonArray(ops.map { JsonPrimitive(it.value) })) }
        value.algorithm?.let { put("alg", JsonPrimitive(it.value)) }
        value.keyId?.let { put("kid", JsonPrimitive(it)) }
        value.x509Url?.let { put("x5u", JsonPrimitive(it)) }
        value.x509CertificateChain?.let { chain -> put("x5c", JsonArray(chain.map { JsonPrimitive(it) })) }
        value.x509CertificateSha1Thumbprint?.let { put("x5t", JsonPrimitive(it)) }
        value.x509CertificateSha256Thumbprint?.let { put("x5t#S256", JsonPrimitive(it)) }
        value.additionalParameters.forEach { (key, value) -> put(key, value) }
    }
    
    private val standardFields = setOf(
        "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
        "n", "e", "d", "p", "q", "dp", "dq", "qi", // RSA
        "crv", "x", "y", // EC
        "k" // Symmetric
    )
}

/**
 * Extension properties and functions for JsonWebKey type checking and convenience.
 */

/**
 * Determines if this is a private key based on the key type.
 */
public val JsonWebKey.isPrivateKey: Boolean
    get() = when (this) {
        is RsaPrivateJsonWebKey -> true
        is EcPrivateJsonWebKey -> true
        is SymmetricJsonWebKey -> true // Symmetric keys contain the secret
        else -> false
    }

/**
 * Determines if this is a public key based on the key type.
 */
public val JsonWebKey.isPublicKey: Boolean
    get() = when (this) {
        is RsaPublicJsonWebKey -> true
        is EcPublicJsonWebKey -> true
        is SymmetricJsonWebKey -> false // Symmetric keys are neither public nor private in the traditional sense
        else -> false
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
    
    /**
     * Finds all RSA keys in the set.
     */
    public fun findRsaKeys(): List<RsaJsonWebKey> = keys.filterIsInstance<RsaJsonWebKey>()
    
    /**
     * Finds all EC keys in the set.
     */
    public fun findEcKeys(): List<EcJsonWebKey> = keys.filterIsInstance<EcJsonWebKey>()
    
    /**
     * Finds all symmetric keys in the set.
     */
    public fun findSymmetricKeys(): List<SymmetricJsonWebKey> = keys.filterIsInstance<SymmetricJsonWebKey>()
}