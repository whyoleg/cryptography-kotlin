/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

public sealed interface JwsObject : JoseObject {
    public val signatures: List<Signature>

    public fun toJsonString(
        /*named*/preferFlattened: Boolean = false,
        /*named*/detachedPayload: Boolean = false, // if true, payload will not be encoded
    ): String

    public sealed interface Signature {
        public val signature: ByteArray
        public val headers: JwsHeaders
    }

    public sealed interface Compact : JwsObject, JoseObject.Compact {
        public val signature: ByteArray

        override val header: JwsHeader // protected only

        // single signature with only protected header
        override val signatures: List<Signature>

        public fun toCompactString(/*named*/detachedPayload: Boolean = false): String
    }

    public companion object {
        public fun parseCompactString(string: String): Compact = TODO()
        public fun parseCompactString(string: String, detachedPayload: ByteArray): Compact = TODO()

        public fun parseJsonString(string: String): JwsObject = TODO()
        public fun parseJsonString(string: String, detachedPayload: ByteArray): JwsObject = TODO()
    }
}

// TODO: implement equals, hashcode, tostring
//private class JwsObjectImpl private constructor(
//    public val payload: ByteArray,
//    public val signatures: List<Signature>,
//) {
//    public val signature: Signature get() = signatures.single() // TODO: better error
//
//    // only in case of single signature
//    // will encode only protected headers
//    public fun toCompactString(): String {
//        val signature = this.signature
//        return buildString {
//            appendSigningInput(signature.headers.protected, payload)
//            append('.')
//            Base64Url.encodeToAppendable(
//                source = signature.signature,
//                destination = this
//            )
//        }
//    }
//
////    public class GeneralJson(
////        public val payload: ByteArray, // base64url
////        public val signatures: List<Signature>,
////    ) {
////        public class Signature(
////            public val protected: String,
////            public val header: String, // json object
////            public val signature: ByteArray, // base64url
////        )
////    }
////
////    public class FlattenedJson(
////        public val payload: ByteArray, // base64url
////        public val protected: String,
////        public val header: String, // json object
////        public val signature: ByteArray, // base64url
////    )
////
////    public class Compact(
////        public val payload: ByteArray, // base64url
////        public val protected: String,
////        public val signature: ByteArray, // base64url
////    )
//}