/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import kotlinx.io.*

internal class SinkOutput(
    private val sink: Sink,
) : BinaryOutput() {
    override fun write(byte: Byte) {
        sink.writeByte(byte)
    }

    override fun write(bytes: ByteArray) {
        sink.write(bytes)
    }

    override fun write(output: BinaryOutput) {
        output as SinkOutput
        output.sink.transferFrom(sink)
    }

    override fun newBinaryOutput(): BinaryOutput {
        TODO("Not yet implemented")
    }
}
