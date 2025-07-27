/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.json.*

// TODO: nested typealias
public typealias JsonWebSignatureSigner = (header: JsonWebSignatureObject.Header, signingInput: ByteArray) -> ByteArray
public typealias JsonWebSignatureVerifier = (header: JsonWebSignatureObject.Header, signingInput: ByteArray, signature: ByteArray) -> Unit

// TODO: nice to have an ability to decode payload to json object, string, byteArray - may be create a separate class for it?
// TODO: implement equals, hashcode, tostring
public class JsonWebSignatureObject private constructor(
    public val payload: ByteArray,
    public val signatures: List<Signature>,
) {
    public val signature: Signature get() = signatures.single() // TODO: better error

    // only in case of single signature
    // will encode only protected headers
    public fun toCompactString(): String {
        val signature = this.signature
        return buildString {
            appendSigningInput(signature, payload)
            append('.')
            Base64Url.encodeToAppendable(
                source = signature.signature,
                destination = this
            )
        }
    }

    // only in case of single signature
    public fun toFlattenedJsonString(): String {
        TODO()
    }

    public fun toJsonString(): String {
        TODO()
    }

    @DelicateJoseApi
    public inline fun verifySignatures(verifier: JsonWebSignatureVerifier) {
        signatures.forEach {
            verifier.invoke(it.header, encodeSigningInput(it, payload), it.signature)
        }
    }

    public class Signature internal constructor(
        public val protectedHeader: Header,
        public val unprotectedHeader: Header,
        public val header: Header,
        public val signature: ByteArray,
    ) {
        init {
            checkNotNull(header.algorithmOrNull)
        }
    }

    @Serializable
    /*@JvmInline*/
    public /*value*/ class Algorithm(public val value: String) {
        public companion object {
            public val HS256: Algorithm = Algorithm("HS256")
        }
    }

    // TODO: should be possible to use JWT claims in header (may be only during encryption? probably everyone uses it in jws too)
    public interface Header : JoseHeader {
        public val algorithm: Algorithm get() = algorithmOrNull ?: error("'alg' header parameter is missing")
        public val algorithmOrNull: Algorithm?
            get() = decodeParameter("alg", Algorithm.serializer())

        // TODO: add other fields

        // TODO: add ability to create header from fields/parameters

        public companion object Parser : JoseHeader.Parser<Header> {
            override fun fromJsonObject(obj: JsonObject): Header {
                return Json.JoseCompliant.decodeFromJsonElement(Impl.serializer(), obj)
            }

            override fun fromJsonString(string: String): Header {
                return Json.JoseCompliant.decodeFromString(Impl.serializer(), string)
            }

            public fun fromFields(
                algorithm: Algorithm?,
            ): Header = Impl(
                algorithmOrNull = algorithm
            )

            // TODO: override toString
            // TODO: recheck on how to implement equals/hashCode for all headers
            @Serializable
            private class Impl(
                @SerialName("alg")
                override val algorithmOrNull: Algorithm?,
            ) : Header {
                override fun toJsonObject(): JsonObject {
                    return Json.JoseCompliant.encodeToJsonElement(kotlinx.serialization.serializer(), this).jsonObject
                }

                override fun toJsonString(): String {
                    return Json.JoseCompliant.encodeToString(kotlinx.serialization.serializer(), this)
                }
            }
        }

        // override vs throw strategy (may be other name, like mergeWith or concatStrict)
        public operator fun plus(other: Header): Header {}

        public object Factory {
            public fun fromJsonString(string: String): Header {}
            public fun fromJsonObject(obj: JsonObject): Header {}
            public fun fromFields(
                algorithm: Algorithm?,
            ): Header {
            }
        }
    }

    public companion object {
        // TODO: decide on name here: of/create/from/etc
        public inline fun <H : Header> create(
            header: H,
            payload: ByteArray,
            signer: JsonWebSignatureSigner<H>,
        ): JsonWebSignatureObject<H> {
            TODO()
        }

        // TODO: delicate API - is it needed?
        @DelicateJoseApi
        public fun <H : Header> createSigned(
            header: H,
            payload: ByteArray,
            signature: ByteArray,
        ): JsonWebSignatureObject<H> {
            TODO()
        }

        public inline fun <H : Header> create(
            payload: ByteArray,
            headers: List<H>, // multiple signatures
            signer: JsonWebSignatureSigner<H>,
        ): JsonWebSignatureObject<H> {
            TODO()
        }

        public inline fun parseCompactString(
            signature: String,
            verifier: JsonWebSignatureVerifier<Header>,
        ): JsonWebSignatureObject<Header> = parseCompactString(Header.Parser, signature, verifier)

        @OptIn(DelicateJoseApi::class)
        public inline fun <H : Header> parseCompactString(
            parser: JoseHeader.Parser<H>,
            signature: String,
            verifier: JsonWebSignatureVerifier<H>,
        ): JsonWebSignatureObject<H> {
            val jws = parseCompactStringUnverified(parser, signature)
            jws.verifySignatures(verifier)
            return jws
        }

        // TODO: handles both flattened and general variants?
        public inline fun parseJsonString(
            signature: String,
            verifier: JsonWebSignatureVerifier<Header>,
        ): JsonWebSignatureObject<Header> = parseJsonString(Header.Parser, signature, verifier)

        public inline fun <H : Header> parseJsonString(
            parser: JoseHeader.Parser<H>,
            signature: String,
            verifier: JsonWebSignatureVerifier<H>,
        ): JsonWebSignatureObject<H> {
            TODO()
        }

        @DelicateJoseApi
        public fun <H : Header> parseCompactStringUnverified(parser: JoseHeader.Parser<H>, signature: String): JsonWebSignatureObject<H> {
            val (header, payload, signature) = parseCompactString(signature, 3)

            return JsonWebSignatureObject(
                payload = Base64Url.decode(payload),
                signatures = listOf(
                    Signature(
                        protectedHeader = parser.fromJsonString(Base64Url.decode(header).decodeToString()),
                        unprotectedHeader = TODO(), // empty
                        header = TODO(), // empty
                        signature = Base64Url.decode(signature)
                    )
                )
            )
        }

        @DelicateJoseApi
        public fun <H : Header> parseJsonStringUnverified(parser: JoseHeader.Parser<H>, signature: String): JsonWebSignatureObject<H> {
            TODO()
        }

        private fun StringBuilder.appendSigningInput(signature: Signature<*>, payload: ByteArray) {
            Base64Url.encodeToAppendable(
                source = signature.protectedHeader.toJsonString().encodeToByteArray(),
                destination = this
            )
            append('.')
            Base64Url.encodeToAppendable(
                source = payload,
                destination = this
            )
        }

        @PublishedApi
        internal fun encodeSigningInput(signature: Signature<*>, payload: ByteArray): ByteArray {
            return buildString {
                appendSigningInput(signature, payload)
            }.encodeToByteArray()
        }

    }


//    public class GeneralJson(
//        public val payload: ByteArray, // base64url
//        public val signatures: List<Signature>,
//    ) {
//        public class Signature(
//            public val protected: String,
//            public val header: String, // json object
//            public val signature: ByteArray, // base64url
//        )
//    }
//
//    public class FlattenedJson(
//        public val payload: ByteArray, // base64url
//        public val protected: String,
//        public val header: String, // json object
//        public val signature: ByteArray, // base64url
//    )
//
//    public class Compact(
//        public val payload: ByteArray, // base64url
//        public val protected: String,
//        public val signature: ByteArray, // base64url
//    )
}
