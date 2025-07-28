/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import dev.whyoleg.cryptography.serialization.jose.v0.JwsObject.Companion.appendSigningInput


public typealias JwsSigner = (header: JwsHeader, signingInput: ByteArray) -> ByteArray
public typealias JwsVerifier = (header: JwsHeader, signingInput: ByteArray, signature: ByteArray) -> Unit

public sealed interface JwsObject {
    public val payload: ByteArray
    public val signatures: List<Signature>

    // TODO: naming?
    public val signature: Signature

    // NOTE: ignores unprotected headers? or throws?
    public fun toCompactString(): String

    // TODO: decide on those three variations
    public fun toFlattenedJsonString(): String     // only in case of single signature
    public fun toGeneralJsonString(): String
    public fun toJsonString(): String // will prefer flattened json if one signature

    // most likely it's enough to have only this one
    // if preferFlattened and there is only one signature - flattened, otherwise general json
    public fun toJsonString(/*named*/preferFlattened: Boolean = true): String

    public sealed interface Signature {
        public val header: JwsObjectHeader
        public val signature: ByteArray
    }

    public companion object {
        @OptIn(DelicateJoseApi::class)
        public inline fun sign(payload: ByteArray, header: JwsObjectHeader, signer: JwsSigner): JwsObject {
            create(
                payload = payload,
                headers = listOf(jwsObjectHeader {
                    protected.fromHeader(header)
                }),
                signer = signer
            )


            val signingInput = encodeSigningInput()
            val signature = signer.invoke(header, signingInput)
            return createPresigned(payload, header, signature)
        }

        // multiple signatures
        public inline fun sign(payload: ByteArray, headers: List<JwsObjectHeader>, signer: JwsSigner): JwsObject = TODO()

        @OptIn(DelicateJoseApi::class)
        public inline fun parseCompactString(string: String, verifier: JwsVerifier): JwsObject {
            val jws = parseCompactStringUnverified(string)
            jws.verifySignatures(verifier)
            return jws
        }

        // handles both flattened and general variants?
        @OptIn(DelicateJoseApi::class)
        public inline fun parseJsonString(signature: String, verifier: JwsVerifier): JwsObject {
            val jws = parseJsonStringUnverified(signature)
            jws.verifySignatures(verifier)
            return jws
        }


        // TODO: presigned and `unverified` are just candidates for public api now
        @PublishedApi
        internal fun presigned(payload: ByteArray, header: JwsObjectHeader, signature: ByteArray): JwsObject {
            return JwsObject(
                payload = payload,
                signatures = listOf(
                    Signature(
                        protectedHeader = header,
                        unprotectedHeader = JwsHeader.Empty,
                        header = header,
                        signature = signature
                    )
                )
            )
        }

        @PublishedApi
        internal fun presigned(payload: ByteArray, headers: List<JwsObjectHeader>, signature: ByteArray): JwsObject = TODO()

        @PublishedApi
        internal fun parseCompactStringUnverified(string: String): JwsObject {
            val (header, payload, signature) = parseCompactString(signature, 3)

            return JwsObject(
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

        @PublishedApi
        internal fun parseJsonStringUnverified(string: String): JwsObject {
            TODO()
        }

        @PublishedApi
        internal fun encodeSigningInput(signature: Signature, payload: ByteArray): ByteArray {
            return buildString {
                appendSigningInput(signature.protectedHeader, payload)
            }.encodeToByteArray()
        }

        private fun StringBuilder.appendSigningInput(signature: Signature, payload: ByteArray) {
            appendSigningInput(signature.protectedHeader, payload)
        }

        private fun StringBuilder.appendSigningInput(header: JwsHeader, payload: ByteArray) {
            Base64Url.encodeToAppendable(
                source = header.toJsonString().encodeToByteArray(),
                destination = this
            )
            append('.')
            Base64Url.encodeToAppendable(
                source = payload,
                destination = this
            )
        }
    }
}

@DelicateJoseApi
public inline fun JwsSignatureHolder.verifyFor(payload: ByteArray, verifier: JwsVerifier) {
    verifier.invoke(header.protected, JwsObject.encodeSigningInput(this, payload), signature)
}

@DelicateJoseApi
public inline fun JwsObject.verify(verifier: JwsVerifier) {
    signatures.forEach {
        verifier.invoke(it.header.protected, JwsObject.encodeSigningInput(it, payload), it.signature)
    }
}

// TODO: implement equals, hashcode, tostring
private class JwsObjectImpl private constructor(
    public val payload: ByteArray,
    public val signatures: List<Signature>,
) {
    public val signature: Signature get() = signatures.single() // TODO: better error

    // only in case of single signature
    // will encode only protected headers
    public fun toCompactString(): String {
        val signature = this.signature
        return buildString {
            appendSigningInput(signature.headers.protected, payload)
            append('.')
            Base64Url.encodeToAppendable(
                source = signature.signature,
                destination = this
            )
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
}
