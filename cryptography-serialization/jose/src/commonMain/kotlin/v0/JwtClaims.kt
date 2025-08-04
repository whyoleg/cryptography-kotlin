/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*

public sealed interface JwtClaims {
    // "iss" Issuer claim (String)
    public val issuer: String?

    public fun toJsonObject(): JsonObject
    public fun toJsonString(): String

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T

    public operator fun contains(key: String): Boolean
    public fun <T> get(key: String, serializer: DeserializationStrategy<T>): T
    public fun <T> getOrNull(key: String, serializer: DeserializationStrategy<T>): T?

    public object StandardClaims {
//        public val ISSUER = ClaimKey<String>("iss")
//        public val SUBJECT = ClaimKey<String>("sub")
//        public val AUDIENCE = ClaimKey<String>("aud")
//        public val EXPIRATION_TIME = ClaimKey<Long>("exp")
//        public val NOT_BEFORE = ClaimKey<Long>("nbf")
//        public val ISSUED_AT = ClaimKey<Long>("iat")
//        public val JWT_ID = ClaimKey<String>("jti")
    }

    public companion object {
        public fun fromJsonObject(obj: JsonObject): JwtClaims = TODO()
        public fun fromJsonString(string: String): JwtClaims = TODO()
    }
}

public sealed interface JwtClaimsBuilder : JwtClaims {
    override var issuer: String?

    public fun fromJsonObject(obj: JsonObject)
    public fun fromJsonString(string: String)

    public fun <T> fromEncoded(serializer: SerializationStrategy<T>, value: T)

    public fun <T> set(key: String, serializer: SerializationStrategy<T>, value: T)
    public fun remove(key: String)
}

public inline fun jwtClaims(block: JwtClaimsBuilder.() -> Unit): JwtClaims = TODO()
