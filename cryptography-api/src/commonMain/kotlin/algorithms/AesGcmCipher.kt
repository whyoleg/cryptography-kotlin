/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import dev.whyoleg.cryptography.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*

// TODO: associatedData (aad) should be provided in calls - should it be parameters?
public interface AesGcmCipher :
    EncryptPrimitive<AesGcmCipherParameters>,
    BoxEncryptPrimitive<AesGcmCipherParameters, AesGcmCipherBox>,
    StreamingEncryptPrimitive<AesGcmCipherParameters>,
    DecryptPrimitive<AesGcmCipherParameters>,
    BoxDecryptPrimitive<Unit, AesGcmCipherBox>,
    StreamingDecryptPrimitive<AesGcmCipherParameters> {

    public fun encryptToBox(plaintext: ByteString): AesGcmCipherBox {
        // random + default
        val parameters = AesGcmCipherParameters(
            nonce = ByteString(CryptographyRandom.nextBytes(12)),
            tagSize = 16
        )
        return encryptToBox(plaintext, parameters)
    }

    public fun decryptFromBox(cipherbox: AesGcmCipherBox): ByteString {
        return decryptFromBox(cipherbox, Unit)
    }

//    public companion object {
//        public val NONCE_SIZE: Int = 12
//        public val DEFAULT_TAG_SIZE: Int = 16
//    }

    public companion object Tag : AesKey.Tag<AesGcmCipher>
}

// TODO: add boxed primitives
public interface AsyncAesGcmCipher :
    AsyncEncryptPrimitive<AesGcmCipherParameters>,
    AsyncDecryptPrimitive<AesGcmCipherParameters> {

    public companion object Tag : AesKey.Tag<AsyncAesGcmCipher>
}

// TODO: make `nonce` single-use?
public class AesGcmCipherParameters(
    public val nonce: ByteString,
    public val tagSize: Int,
)

public class AesGcmCipherBox : CipherBox {
    public override val combined: ByteString

    public val nonce: ByteString// get() = combined.substring(0, 12)
    public val ciphertext: ByteString// get() = combined.substring(12, combined.size - tagSize)
    public val tag: ByteString// get() = combined.substring(combined.size - tagSize, combined.size)

    public constructor(
        combined: ByteString,
        tagSize: Int,
    ) {
        this.combined = combined
        this.nonce = combined.substring(0, 12)
        this.ciphertext = combined.substring(12, combined.size - tagSize)
        this.tag = combined.substring(combined.size - tagSize, combined.size)

        // TODO
        require(tag.size == tagSize) { "Invalid tag size: ${tag.size}, expected: $tagSize" }
    }

    public constructor(
        nonce: ByteString,
        ciphertext: ByteString,
        tag: ByteString,
    ) {
        this.combined = buildByteString {
            append(nonce)
            append(ciphertext)
            append(tag)
        }
        this.nonce = nonce
        this.ciphertext = ciphertext
        this.tag = tag
    }
}
