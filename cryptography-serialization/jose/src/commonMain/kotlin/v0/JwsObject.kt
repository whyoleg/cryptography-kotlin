/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// TODO: decide on how to support `signature with detached content`
public sealed interface JwsObject : JoseObject {
    public val signatures: List<Signature>

    public sealed interface Signature {
        public val signature: ByteArray
        public val header: JwsCompositeHeader
    }

    public sealed interface Compact : JwsObject, JoseObject.Compact {
        override val header: JwsHeader // protected only
        public val signature: ByteArray

        // single signature
        override val signatures: List<Signature>
    }

    public companion object {
        public fun parseCompactString(string: String): Compact = TODO()
        public fun parseJsonString(string: String): JwsObject = TODO()
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