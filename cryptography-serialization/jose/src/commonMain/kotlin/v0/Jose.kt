/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.io.encoding.*

public val Json.Default.JoseCompliant: Json by lazy {
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = true // TODO?
    }
}

// header = JsonObject/TypeSafeMap/custom-class-impl
public sealed interface JoseHeader : Map<String, JsonElement> {
    public fun <T> decode(deserializer: DeserializationStrategy<T>): T {
        return Json.JoseCompliant.decodeFromJsonElement(deserializer, toJsonObject())
    }

    // TODO: nullable/absent parameter handling
    public fun <T> decodeParameter(name: String, deserializer: DeserializationStrategy<T>): T? {
        return Json.JoseCompliant.decodeFromJsonElement(
            deserializer = deserializer,
            element = get(name) ?: return null
        )
    }

    public fun toJsonObject(): JsonObject = JsonObject(this)
    public fun toJsonString(): String = toJsonObject().toString()
    // override fun toString(): String = toJsonString()

    public interface Parser<H : JoseHeader> {
        public fun fromJsonString(string: String): H
        public fun fromJsonObject(obj: JsonObject): H
    }

    public sealed interface Builder {

    }
}

public class JosePayload private constructor(

) {
    public fun toByteArray(): ByteArray {}
    public fun toUtf8String(): String {} // TODO
    public fun toBase64UrlString(): String {} //
    public fun toJsonElement(): JsonElement {}

    public fun <T> decode(format: StringFormat, serializer: DeserializationStrategy<T>): T {}
    public fun <T> decode(format: BinaryFormat, serializer: DeserializationStrategy<T>): T {}
    public fun <T> decodeJson(serializer: DeserializationStrategy<T>): T {}

    public companion object {
        public fun fromUtf8String(string: String): JosePayload {}
        public fun fromBase64UrlString(string: String): JosePayload {}
        public fun fromJsonElement(element: JsonElement): JosePayload {}
        public fun fromByteArray(bytes: ByteArray): JosePayload {}
    }
}

@RequiresOptIn(
    message = "TODO",
    level = RequiresOptIn.Level.ERROR,
)
public annotation class DelicateJoseApi

internal val Base64Url = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

internal fun parseCompactString(compact: String, expectedParts: Int): List<String> {
    val parts = compact.split('.')
    require(parts.size == expectedParts) {
        "Invalid compact format: expected $expectedParts parts separated by dots, got ${parts.size}"
    }
    return parts
}

private fun test(obj: JsonWebSignatureObject) {
    val c1 = JsonWebTokenClaims.fromJsonString(obj.payload.decodeToString())
    val c2 = JsonWebTokenClaims.fromHeader(obj.signature.header)


    Json.JoseCompliant.decodeFromString<JsonObject>(obj.payload.decodeToString())

    buildJsonObject { }
    JsonWebSignatureObject.Header.fromFields(
        JsonWebSignatureObject.Algorithm.HS256
    )

    val jwt = JsonWebSignatureObject.create(
        JsonWebSignatureObject.Header.fromFields(null),
        Json.JoseCompliant.encodeToString(
            JwtClaims()
        ).encodeToByteArray()
    ) { x, y ->
        x.algorithm
        y
    }.toCompactString()
//    Uuid.parse("test-uuid-v0")
}
