/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.time.*

public sealed interface JwtClaims {
    public val issuer: String? // iss
    public val subject: String? // sub
    public val audience: String? // aud
    public val jwtId: String? //jti

    @ExperimentalTime
    public val expirationTime: Instant? // exp

    @ExperimentalTime
    public val notBeforeTime: Instant? // nbf

    @ExperimentalTime
    public val issuedAtTime: Instant? // iat

    public fun toJsonObject(): JsonObject
    public fun toJsonString(): String

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T

    public operator fun contains(key: String): Boolean
    public fun <T> get(key: String, serializer: DeserializationStrategy<T>): T
    public fun <T> getOrNull(key: String, serializer: DeserializationStrategy<T>): T?

    public companion object {
        public fun fromJsonObject(obj: JsonObject): JwtClaims = TODO()
        public fun fromJsonString(string: String): JwtClaims = TODO()
    }
}

public sealed interface JwtClaimsBuilder : JwtClaims {
    override var issuer: String?
    override var subject: String?
    override var audience: String?
    override var jwtId: String?

    @ExperimentalTime
    override var expirationTime: Instant?

    @ExperimentalTime
    override var notBeforeTime: Instant?

    @ExperimentalTime
    override var issuedAtTime: Instant?

    public fun fromJsonObject(obj: JsonObject)
    public fun fromJsonString(string: String)

    public fun <T> fromEncoded(serializer: SerializationStrategy<T>, value: T)

    public fun <T> set(key: String, serializer: SerializationStrategy<T>, value: T)
    public fun remove(key: String)
}

public inline fun JwtClaims(block: JwtClaimsBuilder.() -> Unit): JwtClaims = TODO()
