/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.algorithms.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.bytestring.*

public class AesGcmCipherBox : CipherBox {
    public override val combined: ByteString

    public val nonce: ByteString// get() = combined.substring(0, 12)
    public val ciphertext: ByteString// get() = combined.substring(12, combined.size - tagSize)
    public val tag: ByteString// get() = combined.substring(combined.size - tagSize, combined.size)

    public constructor(
        combined: ByteString,
        tagSize: BinarySize,
    ) {
        this.combined = combined
        this.nonce = combined.substring(0, 12)
        this.ciphertext = combined.substring(12, combined.size - tagSize.inBytes)
        this.tag = combined.substring(combined.size - tagSize.inBytes, combined.size)

        // TODO
        require(tag.size == tagSize.inBytes) { "Invalid tag size: ${tag.size}, expected: ${tagSize.inBytes}" }
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

    public companion object {
        public val NONCE_SIZE: BinarySize get() = 12.bytes
        public val DEFAULT_TAG_SIZE: BinarySize get() = 16.bytes
    }
}
