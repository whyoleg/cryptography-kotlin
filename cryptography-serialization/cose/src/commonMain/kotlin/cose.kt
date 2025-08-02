/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.cose

public sealed interface CoseObject {
    public fun encodeToByteArray(
        /*named*/detachedContent: Boolean = false,
    ): ByteArray // todo name

    public companion object {
        public fun decodeFromByteArray(bytes: ByteArray): CoseObject = TODO()
        public fun decodeFromByteArray(bytes: ByteArray, detachedContent: ByteArray): CoseObject = TODO()
    }
}

public sealed interface CoseContent {
    public val header: CoseCompositeHeader
    public val payload: ByteArray
}

public sealed interface CoseSign : CoseObject {
    //    public val header: CoseCompositeHeader
//    public val payload: ByteArray
    public val signatures: List<CoseSignature>
}

public sealed interface CoseSignature {
    public val header: CoseCompositeHeader
    public val signature: ByteArray
}

public sealed interface CoseSign1 : CoseObject {
    public val header: CoseCompositeHeader

    //    public val payload: ByteArray
    public val signature: ByteArray
}

public sealed interface CoseEncrypt : CoseObject {
    public val header: CoseCompositeHeader
    public val ciphertext: ByteArray
    public val recipients: List<CoseRecipient>
}

public sealed interface CoseRecipient {
    public val header: CoseCompositeHeader
    public val ciphertext: ByteArray
    public val recipients: List<CoseRecipient>
}

public sealed interface CoseEncrypt0 : CoseObject {
    public val header: CoseCompositeHeader
    public val ciphertext: ByteArray
}

public sealed interface CoseMac : CoseObject {
    public val header: CoseCompositeHeader
    public val payload: ByteArray
    public val tag: ByteArray
    public val recipients: List<CoseRecipient>
}

public sealed interface CoseMac0 : CoseObject {
    public val header: CoseCompositeHeader
    public val payload: ByteArray
    public val tag: ByteArray
}

public sealed interface CoseHeader {
    public val algorithm: Algorithm
    public val contentType: ContentType

    public sealed interface Algorithm {
        public val value: String
    }

    public class ContentType(public val value: String)
}

public sealed interface CoseCompositeHeader {
    public val protected: CoseHeader
    public val unprotected: CoseHeader
}