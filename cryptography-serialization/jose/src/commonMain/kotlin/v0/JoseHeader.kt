/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*

public sealed interface JoseHeader {
    public val type: String? // typ
    public val contentType: String? // cty

    public fun toJsonObject(): JsonObject
    public fun toJsonString(): String

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T

    public operator fun contains(key: String): Boolean
    public fun <T> get(key: String, serializer: DeserializationStrategy<T>): T
    public fun <T> getOrNull(key: String, serializer: DeserializationStrategy<T>): T?

    // TODO: decide on what to do with `critical` parameter
    public fun isCritical(key: String): Boolean
}

// TODO: better naming of `from` functions?
public sealed interface JoseHeaderBuilder : JoseHeader {
    public override var type: String?
    public override var contentType: String?

    public fun fromJsonObject(obj: JsonObject)
    public fun fromJsonString(string: String)

    public fun <T> fromEncoded(serializer: SerializationStrategy<T>, value: T)

    public fun <T> set(key: String, serializer: SerializationStrategy<T>, value: T)
    public fun <T> setCritical(key: String, serializer: SerializationStrategy<T>, value: T)

    public fun remove(key: String)

    public fun critical(key: String)
}

public inline fun <reified T> JoseHeader.decode(): T = decode(serializer())

public inline fun <reified T> JoseHeaderBuilder.fromEncoded(value: T): Unit = fromEncoded(serializer(), value)

public sealed interface JoseHeaders {
    public val protected: JoseHeader
    public val unprotected: JoseHeader

    public val combined: JoseHeader
}

public sealed interface JoseHeadersBuilder : JoseHeaders {
    override val protected: JoseHeaderBuilder
    override val unprotected: JoseHeaderBuilder
}

//private class JoseHeaderImpl private constructor(
//    private var obj: JsonObject?,
//    private var string: String?,
//) : JoseHeader {
//    constructor(obj: JsonObject) : this(obj, null)
//    constructor(string: String) : this(null, string)
//
//    override fun <T> decode(deserializer: DeserializationStrategy<T>): T = when {
//        string != null -> Json.JoseCompliant.decodeFromString(deserializer, string!!)
//        obj != null    -> Json.JoseCompliant.decodeFromJsonElement(deserializer, obj!!)
//        else           -> error("should not happen")
//    }
//
//    override fun toJsonObject(): JsonObject {
//        if (obj == null) obj = Json.JoseCompliant.decodeFromString(JsonObject.serializer(), string!!)
//        return obj!!
//    }
//
//    override fun toJsonString(): String {
//        // TODO: this vs obj.toString()
//        if (string == null) string = Json.JoseCompliant.encodeToString(JsonObject.serializer(), obj!!)
//        return string!!
//    }
//
//    override operator fun plus(other: JoseHeader): JoseHeader {
//        return JoseHeaderImpl(JsonObject(toJsonObject() + other.toJsonObject()))
//    }
//
//    override fun toString(): String = "JoseHeader${toJsonString()}"
//}
