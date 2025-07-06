/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import dev.whyoleg.cryptography.serialization.jose.internal.Base64UrlUtils
import dev.whyoleg.cryptography.serialization.jose.internal.CommonJoseHeader
import dev.whyoleg.cryptography.serialization.jose.internal.JoseCompactSerialization
import dev.whyoleg.cryptography.serialization.jose.internal.JoseCompactUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * JSON Web Signature (JWS) as defined in RFC 7515.
 * 
 * JWS represents content secured with digital signatures or Message Authentication Codes (MACs)
 * using JSON-based data structures.
 */

/**
 * JWS Header parameters as defined in RFC 7515 Section 4.1.
 */
@Serializable
public data class JwsHeader(
    /** Algorithm used for signing/encrypting the JWS */
    @SerialName("alg")
    val algorithm: JwsAlgorithm,
    /** JWS and JWE Type parameter */
    @SerialName("typ")
    override val type: String? = null,
    /** Content Type parameter */
    @SerialName("cty")
    override val contentType: String? = null,
    /** Key ID hint indicating which key was used to secure the JWS */
    @SerialName("kid")
    override val keyId: String? = null,
    /** JSON Web Key parameter */
    @SerialName("jwk")
    override val jsonWebKey: JsonWebKey? = null,
    /** X.509 URL parameter */
    @SerialName("x5u")
    override val x509Url: String? = null,
    /** X.509 Certificate Chain parameter */
    @SerialName("x5c")
    override val x509CertificateChain: List<String>? = null,
    /** X.509 Certificate SHA-1 Thumbprint parameter */
    @SerialName("x5t")
    override val x509CertificateSha1Thumbprint: String? = null,
    /** X.509 Certificate SHA-256 Thumbprint parameter */
    @SerialName("x5t#S256")
    override val x509CertificateSha256Thumbprint: String? = null,
    /** Critical parameter - identifies which extensions are critical */
    @SerialName("crit")
    override val critical: List<String>? = null,
    /** Additional header parameters */
    override val additionalParameters: Map<String, JsonElement> = emptyMap()
) : CommonJoseHeader

/**
 * JSON Web Signature Compact Serialization format.
 * 
 * Represents a JWS in the Compact Serialization format:
 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
 * BASE64URL(JWS Payload) || '.' ||
 * BASE64URL(JWS Signature)
 */
@Serializable
public data class JwsCompact(
    val header: JwsHeader,
    val payload: ByteArray,
    val signature: ByteArray
) : JoseCompactSerialization {
    /**
     * Encodes the JWS as a compact serialization string.
     */
    override fun encode(): String {
        val headerEncoded = Base64UrlUtils.encode(getHeaderJson())
        val payloadEncoded = Base64UrlUtils.encode(payload)
        val signatureEncoded = Base64UrlUtils.encode(signature)
        
        return JoseCompactUtils.createCompactString(headerEncoded, payloadEncoded, signatureEncoded)
    }
    
    override fun getHeaderJson(): String = Json.encodeToString(JwsHeader.serializer(), header)
    
    /**
     * Returns the signing input (header.payload) for signature verification.
     */
    public fun getSigningInput(): ByteArray {
        val headerEncoded = Base64UrlUtils.encode(getHeaderJson())
        val payloadEncoded = Base64UrlUtils.encode(payload)
        
        return "$headerEncoded.$payloadEncoded".encodeToByteArray()
    }
    
    public companion object {
        /**
         * Decodes a JWS from its compact serialization string.
         */
        public fun decode(jwsString: String): JwsCompact {
            val parts = JoseCompactUtils.parseCompactString(jwsString, 3)
            
            val headerJson = Base64UrlUtils.decodeToString(parts[0])
            val payload = Base64UrlUtils.decode(parts[1])
            val signature = Base64UrlUtils.decode(parts[2])
            
            val header = Json.decodeFromString(JwsHeader.serializer(), headerJson)
            
            return JwsCompact(header, payload, signature)
        }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        
        other as JwsCompact
        
        if (header != other.header) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!signature.contentEquals(other.signature)) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * JWS Signature for JSON Serialization format.
 */
@Serializable
public data class JwsSignature(
    /** Protected header parameters (base64url encoded) */
    @SerialName("protected")
    val protectedHeader: String? = null,
    /** Unprotected header parameters */
    @SerialName("header")
    val unprotectedHeader: JwsHeader? = null,
    /** The signature value */
    @SerialName("signature")
    val signature: String
)

/**
 * JSON Web Signature JSON Serialization format.
 * 
 * Represents a JWS in the JSON Serialization format as defined in RFC 7515 Section 7.2.
 */
@Serializable
public data class JwsJson(
    /** The JWS payload */
    @SerialName("payload")
    val payload: String,
    /** Array of signature objects for General JSON Serialization, single object for Flattened */
    @SerialName("signatures")
    val signatures: List<JwsSignature>? = null,
    /** For Flattened JSON Serialization - protected header */
    @SerialName("protected")
    val protectedHeader: String? = null,
    /** For Flattened JSON Serialization - unprotected header */
    @SerialName("header")
    val unprotectedHeader: JwsHeader? = null,
    /** For Flattened JSON Serialization - signature */
    @SerialName("signature")
    val signature: String? = null
) {
    /**
     * Converts this JSON serialization to compact serialization if it contains exactly one signature.
     */
    public fun toCompact(): JwsCompact? {
        // Handle Flattened JSON Serialization
        if (signatures == null && signature != null && protectedHeader != null) {
            val headerJson = Base64UrlUtils.decodeToString(protectedHeader)
            val header = Json.decodeFromString(JwsHeader.serializer(), headerJson)
            val payloadBytes = Base64UrlUtils.decode(payload)
            val signatureBytes = Base64UrlUtils.decode(signature)
            
            return JwsCompact(header, payloadBytes, signatureBytes)
        }
        
        // Handle General JSON Serialization with single signature
        if (signatures?.size == 1) {
            val sig = signatures.first()
            if (sig.protectedHeader != null) {
                val headerJson = Base64UrlUtils.decodeToString(sig.protectedHeader)
                val header = Json.decodeFromString(JwsHeader.serializer(), headerJson)
                val payloadBytes = Base64UrlUtils.decode(payload)
                val signatureBytes = Base64UrlUtils.decode(sig.signature)
                
                return JwsCompact(header, payloadBytes, signatureBytes)
            }
        }
        
        return null
    }
    
    /**
     * Checks if this is a flattened JSON serialization.
     */
    public val isFlattened: Boolean
        get() = signatures == null && signature != null
    
    /**
     * Checks if this is a general JSON serialization.
     */
    public val isGeneral: Boolean
        get() = signatures != null
    
    public companion object {
        /**
         * Creates a flattened JSON serialization from a compact JWS.
         */
        public fun fromCompact(compact: JwsCompact): JwsJson {
            val protectedHeader = Base64UrlUtils.encode(compact.getHeaderJson())
            val payload = Base64UrlUtils.encode(compact.payload)
            val signature = Base64UrlUtils.encode(compact.signature)
            
            return JwsJson(
                payload = payload,
                protectedHeader = protectedHeader,
                signature = signature
            )
        }
    }
}