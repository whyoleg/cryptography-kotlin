/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.cryptography.jose

import kotlinx.serialization.Serializable
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
) {
    /**
     * Encodes the JWT as a compact serialization string.
     * Format: base64url(header).base64url(payload).base64url(signature)
     */
    public fun encode(): String {
        // TODO: Implement JWT encoding
        throw NotImplementedError("JWT encoding not yet implemented")
    }
    
    companion object {
        /**
         * Decodes a JWT from its compact serialization string.
         */
        public fun decode(token: String): JsonWebToken {
            // TODO: Implement JWT decoding
            throw NotImplementedError("JWT decoding not yet implemented")
        }
    }
}

/**
 * JWT Header as defined in RFC 7515.
 */
@Serializable
public data class JwtHeader(
    /** Algorithm used for signing/encrypting the JWT */
    val alg: String,
    /** Type of the token, typically "JWT" */
    val typ: String? = "JWT",
    /** Key ID hint indicating which key was used to secure the JWT */
    val kid: String? = null
)

/**
 * JWT Payload containing claims as defined in RFC 7519.
 */
@Serializable
public data class JwtPayload(
    /** Issuer - identifies the principal that issued the JWT */
    val iss: String? = null,
    /** Subject - identifies the principal that is the subject of the JWT */
    val sub: String? = null,
    /** Audience - identifies the recipients that the JWT is intended for */
    val aud: String? = null,
    /** Expiration Time - identifies the expiration time on or after which the JWT MUST NOT be accepted */
    val exp: Long? = null,
    /** Not Before - identifies the time before which the JWT MUST NOT be accepted */
    val nbf: Long? = null,
    /** Issued At - identifies the time at which the JWT was issued */
    val iat: Long? = null,
    /** JWT ID - provides a unique identifier for the JWT */
    val jti: String? = null,
    /** Additional custom claims */
    val customClaims: Map<String, JsonElement> = emptyMap()
)