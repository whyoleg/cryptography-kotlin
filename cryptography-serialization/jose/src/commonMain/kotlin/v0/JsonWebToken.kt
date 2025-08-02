/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*

// "iss" Issuer claim (String)

// can it be @Serializable?
public sealed interface JsonWebToken {
    public val issuer: String

    public operator fun contains(key: String): Boolean
    public operator fun <T> get(key: String, serializer: DeserializationStrategy<T>): T
    public fun <T> getOrNull(key: String, serializer: DeserializationStrategy<T>): T?

    // for extensibility?
    public operator fun contains(key: ClaimKey<*>): Boolean = contains(key.name)
    public operator fun <T> get(key: ClaimKey<T>): T = get(key.name, key.serializer)
    public fun <T> getOrNull(key: ClaimKey<T>): T? = getOrNull(key.name, key.serializer)

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T

    public fun toJsonObject(): JsonObject
    public fun toJsonString(): String

    // claims can be used as header parameters, not the other way around
    public interface ClaimKey<T> : JoseHeader.ParameterKey<T>

    public object StandardClaims {
//        public val ISSUER = ClaimKey<String>("iss")
//        public val SUBJECT = ClaimKey<String>("sub")
//        public val AUDIENCE = ClaimKey<String>("aud")
//        public val EXPIRATION_TIME = ClaimKey<Long>("exp")
//        public val NOT_BEFORE = ClaimKey<Long>("nbf")
//        public val ISSUED_AT = ClaimKey<Long>("iat")
//        public val JWT_ID = ClaimKey<String>("jti")
    }
}

public sealed interface JsonWebTokenBuilder : JsonWebToken {
    override var issuer: String

    public fun fromJsonObject(obj: JsonObject)
    public fun fromJsonString(string: String)

    public fun <T> fromEncoded(serializer: SerializationStrategy<T>, value: T)

    public fun <T> put(key: String, serializer: SerializationStrategy<T>, value: T)
    public fun remove(key: String)

    public fun <T> put(key: JsonWebToken.ClaimKey<T>, value: T)
    public fun remove(key: JsonWebToken.ClaimKey<*>)
}

public inline fun jsonWebToken(block: JsonWebTokenBuilder.() -> Unit): JsonWebToken = TODO()
