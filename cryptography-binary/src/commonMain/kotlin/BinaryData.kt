/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.binary

import dev.whyoleg.cryptography.binary.BinarySize.Companion.bytes
import kotlin.io.encoding.*
import kotlin.jvm.*

@JvmInline
public value class BinaryData private constructor(private val bytes: ByteArray) {
    public val size: BinarySize get() = bytes.size.bytes

    public fun toByteArray(): ByteArray = bytes.copyOf()

    public fun toUtf8String(): String = bytes.decodeToString()

    @ExperimentalEncodingApi
    public fun toBase64String(base64: Base64 = Base64): String = base64.encode(bytes)

    @ExperimentalStdlibApi
    public fun toHexString(format: HexFormat = HexFormat.Default): String = bytes.toHexString(format)

    public companion object {
        public fun fromByteArray(bytes: ByteArray): BinaryData = BinaryData(bytes)

        public fun fromUtf8String(text: String): BinaryData = BinaryData(text.encodeToByteArray())

        @ExperimentalStdlibApi
        public fun fromHexString(text: String, format: HexFormat = HexFormat.Default): BinaryData = BinaryData(text.hexToByteArray(format))

        @ExperimentalEncodingApi
        public fun fromBase64String(text: String, base64: Base64): BinaryData = BinaryData(base64.decode(text))
    }
}
