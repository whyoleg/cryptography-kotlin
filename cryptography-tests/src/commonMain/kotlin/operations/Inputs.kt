/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

// inputs of test vectors

// hex encoded bytes, whitespaces are ignored, so values could be copied from specifications as is
fun hex(value: String): ByteString = value.filterNot(Char::isWhitespace).hexToByteString()

// UTF-8 encoded text
fun text(value: String): ByteString = value.encodeToByteString()

// inputs of generated test data

fun randomBytes(size: Int): ByteString = ByteString(CryptographyRandom.nextBytes(size))

// we do test only Safari and Chrome
fun TestLimitationScope.failsOnEmptyInput(inputSize: Int): TestLimitation? = when {
    inputSize == 0 && provider.isWebCrypto && platform.isBrowserSafari -> fails("Empty input is not supported in Safari")
    else                                                               -> null
}

// used for derived negative checks
internal fun ByteString.flipBit(index: Int = size / 2): ByteString {
    require(isNotEmpty()) { "Can't flip a bit in an empty ByteString" }
    val bytes = toByteArray()
    bytes[index] = (bytes[index].toInt() xor 1).toByte()
    return ByteString(bytes)
}

// the first byte is changed, as some operations use only a prefix of the input (f.e. ECDSA without digest)
internal fun ByteString.tamper(): ByteString = if (isEmpty()) ByteString(0) else flipBit(0)

internal fun Buffer(bytes: ByteString): Buffer = Buffer().apply { write(bytes) }

internal fun Buffer.bufferedSource(): Source = (this as RawSource).buffered()
internal fun Buffer.bufferedSink(): Sink = (this as RawSink).buffered()
