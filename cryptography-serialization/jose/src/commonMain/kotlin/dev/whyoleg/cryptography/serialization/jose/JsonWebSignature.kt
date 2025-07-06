/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

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
    val type: String? = null,
    /** Content Type parameter */
    @SerialName("cty")
    val contentType: String? = null,
    /** Key ID hint indicating which key was used to secure the JWS */
    @SerialName("kid")
    val keyId: String? = null,
    /** JSON Web Key parameter */
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,
    /** X.509 URL parameter */
    @SerialName("x5u")
    val x509Url: String? = null,
    /** X.509 Certificate Chain parameter */
    @SerialName("x5c")
    val x509CertificateChain: List<String>? = null,
    /** X.509 Certificate SHA-1 Thumbprint parameter */
    @SerialName("x5t")
    val x509CertificateSha1Thumbprint: String? = null,
    /** X.509 Certificate SHA-256 Thumbprint parameter */
    @SerialName("x5t#S256")
    val x509CertificateSha256Thumbprint: String? = null,
    /** Critical parameter - identifies which extensions are critical */
    @SerialName("crit")
    val critical: List<String>? = null,
    /** Additional header parameters */
    val additionalParameters: Map<String, JsonElement> = emptyMap()
)

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
) {
    /**
     * Encodes the JWS as a compact serialization string.
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun encode(): String {
        val headerJson = Json.encodeToString(JwsHeader.serializer(), header)
        val headerEncoded = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
        val payloadEncoded = Base64.UrlSafe.encode(payload).trimEnd('=')
        val signatureEncoded = Base64.UrlSafe.encode(signature).trimEnd('=')
        
        return "$headerEncoded.$payloadEncoded.$signatureEncoded"
    }
    
    /**
     * Returns the signing input (header.payload) for signature verification.
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun getSigningInput(): ByteArray {
        val headerJson = Json.encodeToString(JwsHeader.serializer(), header)
        val headerEncoded = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
        val payloadEncoded = Base64.UrlSafe.encode(payload).trimEnd('=')
        
        return "$headerEncoded.$payloadEncoded".encodeToByteArray()
    }
    
    public companion object {
        /**
         * Decodes a JWS from its compact serialization string.
         */
        @OptIn(ExperimentalEncodingApi::class)
        public fun decode(jwsString: String): JwsCompact {
            val parts = jwsString.split('.')
            require(parts.size == 3) { "Invalid JWS format: expected 3 parts separated by dots" }
            
            val headerJson = Base64.UrlSafe.decode(parts[0].padBase64()).decodeToString()
            val payload = Base64.UrlSafe.decode(parts[1].padBase64())
            val signature = Base64.UrlSafe.decode(parts[2].padBase64())
            
            val header = Json.decodeFromString(JwsHeader.serializer(), headerJson)
            
            return JwsCompact(header, payload, signature)
        }
        
        private fun String.padBase64(): String {
            val padding = (4 - length % 4) % 4
            return this + "=".repeat(padding)
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
    @OptIn(ExperimentalEncodingApi::class)
    public fun toCompact(): JwsCompact? {
        // Handle Flattened JSON Serialization
        if (signatures == null && signature != null && protectedHeader != null) {
            val headerJson = Base64.UrlSafe.decode(protectedHeader.padBase64()).decodeToString()
            val header = Json.decodeFromString(JwsHeader.serializer(), headerJson)
            val payloadBytes = Base64.UrlSafe.decode(payload.padBase64())
            val signatureBytes = Base64.UrlSafe.decode(signature.padBase64())
            
            return JwsCompact(header, payloadBytes, signatureBytes)
        }
        
        // Handle General JSON Serialization with single signature
        if (signatures?.size == 1) {
            val sig = signatures.first()
            if (sig.protectedHeader != null) {
                val headerJson = Base64.UrlSafe.decode(sig.protectedHeader.padBase64()).decodeToString()
                val header = Json.decodeFromString(JwsHeader.serializer(), headerJson)
                val payloadBytes = Base64.UrlSafe.decode(payload.padBase64())
                val signatureBytes = Base64.UrlSafe.decode(sig.signature.padBase64())
                
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
        @OptIn(ExperimentalEncodingApi::class)
        public fun fromCompact(compact: JwsCompact): JwsJson {
            val headerJson = Json.encodeToString(JwsHeader.serializer(), compact.header)
            val protectedHeader = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
            val payload = Base64.UrlSafe.encode(compact.payload).trimEnd('=')
            val signature = Base64.UrlSafe.encode(compact.signature).trimEnd('=')
            
            return JwsJson(
                payload = payload,
                protectedHeader = protectedHeader,
                signature = signature
            )
        }
        
        private fun String.padBase64(): String {
            val padding = (4 - length % 4) % 4
            return this + "=".repeat(padding)
        }
    }
}