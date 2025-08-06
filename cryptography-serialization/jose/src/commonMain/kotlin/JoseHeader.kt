/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*

@Serializable
public sealed interface JoseHeader {
    public val type: String? // typ
    public val contentType: String? // cty
    public val keyId: String? // kid

    public val jwkSetUrl: String? // jku
    public val jwk: JwkObject? // jwk

    public val x509Url: String? // x5u
    public val x509CertificateChain: List<ByteArray> // x5c
    public val x509CertificateSha1Thumbprint: ByteArray? // x5t
    public val x509CertificateSha256Thumbprint: ByteArray? // x5t#S256

    public fun <T> decode(deserializer: DeserializationStrategy<T>): T
    public fun <T> decodeField(key: String, serializer: DeserializationStrategy<T>): T

    public operator fun contains(key: String): Boolean
}

public sealed interface JoseHeaderBuilder : JoseHeader {
    public override var type: String?
    public override var contentType: String?
    public override var keyId: String?

    public override var jwkSetUrl: String?
    public override var jwk: JwkObject?

    public override var x509Url: String?
    public override var x509CertificateChain: List<ByteArray>
    public override var x509CertificateSha1Thumbprint: ByteArray?
    public override var x509CertificateSha256Thumbprint: ByteArray?

    public fun <T> encode(serializer: SerializationStrategy<T>, value: T)
    public fun <T> encodeField(key: String, serializer: SerializationStrategy<T>, value: T)

    // can be used only inside protected header
    public fun criticalFields(vararg keys: String)
}

public inline fun <reified T> JoseHeader.decode(): T = decode(serializer())

public inline fun <reified T> JoseHeaderBuilder.encode(value: T): Unit = encode(serializer(), value)

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
