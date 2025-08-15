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
    public val headers: CoseHeaders
    public val payload: ByteArray
}

// content.sign().verify()
// content.encrypt().decrypt()
// content.computeMac().verify()

// sign: content+header + [signature headers]
// sign0: content+(header+signature_header)
// encrypt: content+header + [recipient_headers]

// coseObject(content, header, listOf(coseRecipient(header, ciphertext, recipients)))


public sealed interface CoseSign : CoseObject {
    //    public val header: CoseCompositeHeader
//    public val payload: ByteArray
    public val signatures: List<CoseSignature>
}

public sealed interface CoseSignature {
    public val headers: CoseHeaders
    public val signature: ByteArray
}

public sealed interface CoseSign1 : CoseObject {
    public val headers: CoseHeaders

    //    public val payload: ByteArray
    public val signature: ByteArray
}

public sealed interface CoseEncrypt : CoseObject {
    public val headers: CoseHeaders
    public val ciphertext: ByteArray
    public val recipients: List<CoseRecipient>
}

public sealed interface CoseRecipient {
    public val headers: CoseHeaders
    public val ciphertext: ByteArray
    public val recipients: List<CoseRecipient>
}

public sealed interface CoseEncrypt0 : CoseObject {
    public val headers: CoseHeaders
    public val ciphertext: ByteArray
}

public sealed interface CoseMac : CoseObject {
    public val headers: CoseHeaders
    public val payload: ByteArray
    public val tag: ByteArray
    public val recipients: List<CoseRecipient>
}

public sealed interface CoseMac0 : CoseObject {
    public val headers: CoseHeaders
    public val payload: ByteArray
    public val tag: ByteArray
}

public sealed interface CoseContentHeader
public sealed interface CoseMacHeader
public sealed interface CoseSignHeader
public sealed interface CoseEncryptHeader

public sealed interface CoseHeader {
    public val algorithm: Algorithm
    public val contentType: ContentType

    public sealed interface Algorithm {
        public val value: String
    }

    public class ContentType(public val value: String)
}

public sealed interface CoseHeaders {
    public val protected: CoseHeader
    public val unprotected: CoseHeader
}

public sealed interface CoseKey
