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
) {
    /**
     * Encodes the JWT as a compact serialization string.
     * Format: base64url(header).base64url(payload).base64url(signature)
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun encode(): String {
        val headerJson = Json.encodeToString(JwtHeader.serializer(), header)
        val payloadJson = Json.encodeToString(JwtPayload.serializer(), payload)
        
        val headerEncoded = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
        val payloadEncoded = Base64.UrlSafe.encode(payloadJson.encodeToByteArray()).trimEnd('=')
        
        return if (signature != null) {
            "$headerEncoded.$payloadEncoded.$signature"
        } else {
            "$headerEncoded.$payloadEncoded."
        }
    }
    
    public companion object {
        /**
         * Decodes a JWT from its compact serialization string.
         */
        @OptIn(ExperimentalEncodingApi::class)
        public fun decode(token: String): JsonWebToken {
            val parts = token.split('.')
            require(parts.size == 3) { "Invalid JWT format: expected 3 parts separated by dots" }
            
            val headerJson = Base64.UrlSafe.decode(parts[0].padBase64()).decodeToString()
            val payloadJson = Base64.UrlSafe.decode(parts[1].padBase64()).decodeToString()
            val signature = parts[2].takeIf { it.isNotEmpty() }
            
            val header = Json.decodeFromString(JwtHeader.serializer(), headerJson)
            val payload = Json.decodeFromString(JwtPayload.serializer(), payloadJson)
            
            return JsonWebToken(header, payload, signature)
        }
        
        private fun String.padBase64(): String {
            val padding = (4 - length % 4) % 4
            return this + "=".repeat(padding)
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