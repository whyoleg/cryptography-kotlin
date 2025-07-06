/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import dev.whyoleg.cryptography.serialization.jose.internal.Base64UrlUtils
import dev.whyoleg.cryptography.serialization.jose.internal.JoseCompactSerialization
import dev.whyoleg.cryptography.serialization.jose.internal.JoseCompactUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * JSON Web Token (JWT) representation as defined in RFC 7519.
 * 
 * A JWT consists of three parts separated by dots:
 * - Header: contains metadata about the token
 * - Payload: contains the claims
 * - Signature: ensures the token hasn't been tampered with
 */
@Serializable
public data class JsonWebToken(
    val header: JwtHeader,
    val payload: JwtPayload,
    val signature: String? = null
) : JoseCompactSerialization {
    /**
     * Encodes the JWT as a compact serialization string.
     * Format: base64url(header).base64url(payload).base64url(signature)
     */
    override fun encode(): String {
        val headerEncoded = Base64UrlUtils.encode(getHeaderJson())
        val payloadEncoded = Base64UrlUtils.encode(getPayloadJson())
        
        return if (signature != null) {
            JoseCompactUtils.createCompactString(headerEncoded, payloadEncoded, signature)
        } else {
            JoseCompactUtils.createCompactString(headerEncoded, payloadEncoded, "")
        }
    }
    
    override fun getHeaderJson(): String = Json.encodeToString(JwtHeader.serializer(), header)
    
    /**
     * Gets the payload as a JSON string for encoding.
     */
    public fun getPayloadJson(): String = Json.encodeToString(JwtPayload.serializer(), payload)
    
    public companion object {
        /**
         * Decodes a JWT from its compact serialization string.
         */
        public fun decode(token: String): JsonWebToken {
            val parts = JoseCompactUtils.parseCompactString(token, 3)
            
            val headerJson = Base64UrlUtils.decodeToString(parts[0])
            val payloadJson = Base64UrlUtils.decodeToString(parts[1])
            val signature = parts[2].takeIf { it.isNotEmpty() }
            
            val header = Json.decodeFromString(JwtHeader.serializer(), headerJson)
            val payload = Json.decodeFromString(JwtPayload.serializer(), payloadJson)
            
            return JsonWebToken(header, payload, signature)
        }
    }
}

/**
 * JWT Header as defined in RFC 7515.
 */
@Serializable
public data class JwtHeader(
    /** Algorithm used for signing/encrypting the JWT */
    @SerialName("alg")
    val algorithm: JwsAlgorithm,
    /** Type of the token, typically "JWT" */
    @SerialName("typ") 
    val type: String? = "JWT",
    /** Key ID hint indicating which key was used to secure the JWT */
    @SerialName("kid") 
    val keyId: String? = null
)

/**
 * JWT Payload containing claims as defined in RFC 7519.
 */
@Serializable
public data class JwtPayload(
    /** Issuer - identifies the principal that issued the JWT */
    @SerialName("iss")
    val issuer: String? = null,
    /** Subject - identifies the principal that is the subject of the JWT */
    @SerialName("sub")
    val subject: String? = null,
    /** Audience - identifies the recipients that the JWT is intended for */
    @SerialName("aud")
    val audience: List<String>? = null,
    /** Expiration Time - identifies the expiration time on or after which the JWT MUST NOT be accepted */
    @SerialName("exp")
    val expirationTime: Long? = null,
    /** Not Before - identifies the time before which the JWT MUST NOT be accepted */
    @SerialName("nbf")
    val notBefore: Long? = null,
    /** Issued At - identifies the time at which the JWT was issued */
    @SerialName("iat")
    val issuedAt: Long? = null,
    /** JWT ID - provides a unique identifier for the JWT */
    @SerialName("jti")
    val jwtId: String? = null,
    /** Additional custom claims */
    val customClaims: Map<String, JsonElement> = emptyMap()
) {
    /**
     * Convenience property for accessing single audience value.
     */
    val singleAudience: String?
        get() = audience?.singleOrNull()
    
    /**
     * Checks if the JWT is expired at the given time (in seconds since epoch).
     */
    public fun isExpired(currentTime: Long = System.currentTimeMillis() / 1000): Boolean {
        return expirationTime != null && currentTime >= expirationTime
    }
    
    /**
     * Checks if the JWT is not yet valid at the given time (in seconds since epoch).
     */
    public fun isNotYetValid(currentTime: Long = System.currentTimeMillis() / 1000): Boolean {
        return notBefore != null && currentTime < notBefore
    }
    
    /**
     * Checks if the JWT is currently valid (not expired and not before current time).
     */
    public fun isValid(currentTime: Long = System.currentTimeMillis() / 1000): Boolean {
        return !isExpired(currentTime) && !isNotYetValid(currentTime)
    }
}