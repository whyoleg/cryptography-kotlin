/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.time.*

@Serializable(JwtClaimsSerializer::class) // json
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

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T
    public fun <T> decodeField(key: String, deserializer: DeserializationStrategy<T>): T

    public operator fun contains(key: String): Boolean
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

    public fun <T> encode(serializer: SerializationStrategy<T>, value: T)
    public fun <T> encodeField(key: String, serializer: SerializationStrategy<T>, value: T)

    public fun remove(key: String)
}

public inline fun JwtClaims(block: JwtClaimsBuilder.() -> Unit): JwtClaims = TODO()

public inline fun <reified T> JwtClaims.decode(): T = decode(serializer<T>())
public inline fun <reified T> JwtClaims.decodeField(key: String): T = decodeField(key, serializer<T>())

public inline fun <reified T> JwtClaimsBuilder.encode(value: T): Unit = encode(serializer<T>(), value)
public inline fun <reified T> JwtClaimsBuilder.encodeField(key: String, value: T): Unit = encodeField(key, serializer<T>(), value)

internal object JwtClaimsSerializer : KSerializer<JwtClaims> {
    override val descriptor: SerialDescriptor
        get() = TODO("Not yet implemented")

    override fun serialize(encoder: Encoder, value: JwtClaims) {
        TODO("Not yet implemented")
    }

    override fun deserialize(decoder: Decoder): JwtClaims {
        TODO("Not yet implemented")
    }
}
