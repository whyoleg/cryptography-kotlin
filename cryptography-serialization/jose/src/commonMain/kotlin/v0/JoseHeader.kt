/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.reflect.*

public sealed interface JoseHeader {
    public val algorithm: Algorithm

    public val type: Type
    public val contentType: ContentType

    public operator fun contains(key: String): Boolean
    public operator fun <T> get(key: String, serializer: DeserializationStrategy<T>): T
    public fun <T> getOrNull(key: String, serializer: DeserializationStrategy<T>): T?

    // for extensibility?
    public operator fun contains(key: ParameterKey<*>): Boolean = contains(key.name)
    public operator fun <T> get(key: ParameterKey<T>): T = get(key.name, key.serializer)
    public fun <T> getOrNull(key: ParameterKey<T>): T? = getOrNull(key.name, key.serializer)

    // TODO: decide on what to do with `critical` parameter
    public fun isCritical(key: String): Boolean
    public fun isCritical(key: ParameterKey<*>): Boolean

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T

    public fun toJsonObject(): JsonObject
    public fun toJsonString(): String

    // TODO: should it be nested class?
    public interface ParameterKey<T> {
        public val name: String
        public val serializer: KSerializer<T>

        public companion object {
            // can be cached?
            public fun <T> of(name: String, serializer: KSerializer<T>): ParameterKey<T> {
                TODO()
            }

            public inline fun <reified T> of(name: String): ParameterKey<T> = of(name, serializer())
        }
    }

    public sealed interface Algorithm {
        public val value: String
    }

    public class Type(public val value: String) {
        public companion object : ParameterKey<String> by ParameterKey.of("typ") {
            public val JWT: Type = Type("JWT")
        }
    }

    public class ContentType(public val value: String) {
        public companion object : ParameterKey<String> by ParameterKey.of("cty") {
            // public val JSON: ContentType = ContentType("application/json")
        }
    }

    // TODO
//    public object DefaultParameters {
//        public val TYPE: ParameterKey<String> = ParameterKey.of("typ", String.serializer())
//    }
}

// TODO: better naming of `from` functions?
public sealed interface JoseHeaderBuilder : JoseHeader {
    public override var type: JoseHeader.Type
    public override var contentType: JoseHeader.ContentType

    public fun fromJsonObject(obj: JsonObject)
    public fun fromJsonString(string: String)

    public fun <T> fromEncoded(serializer: SerializationStrategy<T>, value: T)

    public fun <T> put(key: String, serializer: SerializationStrategy<T>, value: T)
    public fun <T> putCritical(key: String, serializer: SerializationStrategy<T>, value: T)

    public fun <T> put(key: JoseHeader.ParameterKey<T>, value: T)
    public fun <T> putCritical(key: JoseHeader.ParameterKey<T>, value: T)

    public fun remove(key: String)
    public fun remove(key: JoseHeader.ParameterKey<*>)

    public fun critical(key: String)
    public fun critical(key: JoseHeader.ParameterKey<*>)
}

public inline fun <reified T> JoseHeader.decode(): T = decode(serializer())

public inline fun <reified T> JoseHeaderBuilder.fromEncoded(value: T) {
    fromEncoded(serializer(), value)
}

public operator fun <T> JoseHeader.ParameterKey<T>.getValue(thisRef: JoseHeader, property: KProperty<*>): T {
    return thisRef[this]
}

public operator fun <T> JoseHeader.ParameterKey<T>.setValue(thisRef: JoseHeaderBuilder, property: KProperty<*>, value: T) {
    thisRef.put(this, value)
}

// example of use
//public val JoseHeader.type: String by JoseHeader.DefaultParameters.TYPE
//public var JoseHeaderBuilder.type: String by JoseHeader.DefaultParameters.TYPE

private class JoseHeaderImpl private constructor(
    private var obj: JsonObject?,
    private var string: String?,
) : JoseHeader {
    constructor(obj: JsonObject) : this(obj, null)
    constructor(string: String) : this(null, string)

    override fun <T> decode(deserializer: DeserializationStrategy<T>): T = when {
        string != null -> Json.JoseCompliant.decodeFromString(deserializer, string!!)
        obj != null    -> Json.JoseCompliant.decodeFromJsonElement(deserializer, obj!!)
        else           -> error("should not happen")
    }

    override fun toJsonObject(): JsonObject {
        if (obj == null) obj = Json.JoseCompliant.decodeFromString(JsonObject.serializer(), string!!)
        return obj!!
    }

    override fun toJsonString(): String {
        // TODO: this vs obj.toString()
        if (string == null) string = Json.JoseCompliant.encodeToString(JsonObject.serializer(), obj!!)
        return string!!
    }

    override operator fun plus(other: JoseHeader): JoseHeader {
        return JoseHeaderImpl(JsonObject(toJsonObject() + other.toJsonObject()))
    }

    override fun toString(): String = "JoseHeader${toJsonString()}"
}
