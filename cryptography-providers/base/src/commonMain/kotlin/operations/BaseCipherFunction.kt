/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.base.*
import kotlinx.io.*
import kotlinx.io.unsafe.*

@CryptographyProviderApi
public interface CipherFunction {
    public fun transform(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size): ByteArray
    public fun transformedSource(source: RawSource): RawSource
    public fun transformedSink(sink: RawSink): RawSink
}

// TODO: test with different input/output sizes
@CryptographyProviderApi
public abstract class BaseCipherFunction : CipherFunction, AutoCloseable {
    // block size can be 0/-1 -> stream cipher
    // in case of JDK, `CipherSpi` says it returns `0` in this case, but BC returns `-1` ...
    protected abstract val blockSize: Int

    // returns -1 if it's not known
    protected abstract fun maxOutputSize(inputSize: Int): Int

    // estimates `inputSize` so that next `maxOutputSize(inputSize)` will be less than `expectedMaxOutputSize`
    // returns -1 if it's not possible to estimate size
    protected open fun maxInputSize(initialMaxInputSize: Int, expectedMaxOutputSize: Int): Int {
        check(initialMaxInputSize >= 0) { "initialMaxInputSize must be >= 0, but was $initialMaxInputSize" }
        check(expectedMaxOutputSize >= 0) { "expectedMaxOutputSize must be >= 0, but was $expectedMaxOutputSize" }

        if (maxOutputSize(initialMaxInputSize) <= expectedMaxOutputSize) return initialMaxInputSize
        if (maxOutputSize(0) > expectedMaxOutputSize) return -1

        val stepSize = if (blockSize > 0) blockSize else 16
        var inputSize = initialMaxInputSize - stepSize
        while (inputSize > 0) {
            val outputSize = maxOutputSize(inputSize)
            if (outputSize <= expectedMaxOutputSize) return inputSize
            inputSize -= stepSize
        }
        return -1
    }

    protected open fun transformToByteArray(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size): ByteArray {
        val maxOutputSize = maxOutputSize(endIndex - startIndex)
        val output = ByteArray(maxOutputSize)
        val outputSize = transformIntoByteArray(source, output, 0, startIndex, endIndex)
        return output.ensureSizeExactly(outputSize)
    }

    protected abstract fun transformIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
        endIndex: Int = source.size,
    ): Int

    protected open fun finalizeToByteArray(): ByteArray {
        val maxOutputSize = maxOutputSize(0)
        val output = ByteArray(maxOutputSize)
        val outputSize = finalizeIntoByteArray(output)
        return output.ensureSizeExactly(outputSize)
    }

    protected abstract fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int

    protected open fun transformAndFinalizeToByteArray(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size): ByteArray {
        val maxOutputSize = maxOutputSize(endIndex - startIndex)
        val output = ByteArray(maxOutputSize)
        val outputSize = transformAndFinalizeIntoByteArray(source, output, 0, startIndex, endIndex)
        return output.ensureSizeExactly(outputSize)
    }

    protected open fun transformAndFinalizeIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
        endIndex: Int = source.size,
    ): Int {
        checkBounds(source.size, startIndex, endIndex)
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(endIndex - startIndex))

        val transformedToDestination = transformIntoByteArray(source, destination, destinationOffset, startIndex, endIndex)
        val finalizedToDestination = finalizeIntoByteArray(destination, destinationOffset + transformedToDestination)

        return transformedToDestination + finalizedToDestination
    }

    public override fun transform(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray = use {
        return transformAndFinalizeToByteArray(source, startIndex, endIndex)
    }

    public override fun transformedSource(source: RawSource): RawSource {
        return TransformedSource(source)
    }

    public override fun transformedSink(sink: RawSink): RawSink {
        return TransformedSink(sink)
    }

    @OptIn(UnsafeIoApi::class)
    private fun transformTo(
        inputBuffer: Buffer,
        outputBuffer: Buffer,
        maxInputCount: Long,
    ): Int = UnsafeBufferOperations.readFromHead(inputBuffer) { input, inputStartIndex, inputEndIndex ->
        val maxInputSize = minOf(maxInputCount, (inputEndIndex - inputStartIndex).toLong()).toInt()
        val maxOutputSize = maxOutputSize(maxInputSize)
        val inputSize: Int
        val outputSize: Int
        // can't estimate output size
        if (maxOutputSize == -1) {
            outputSize = -1
            inputSize = -1
        } else if (maxOutputSize <= UnsafeBufferOperations.maxSafeWriteCapacity) {
            outputSize = maxOutputSize
            inputSize = maxInputSize
        } else {
            outputSize = UnsafeBufferOperations.maxSafeWriteCapacity
            inputSize = maxInputSize(maxInputSize, outputSize)
        }

        // can't estimate size to fit for safe output size
        if (inputSize == -1 || outputSize == -1 || outputSize == 0) {
            outputBuffer.write(transformToByteArray(input, inputStartIndex, inputStartIndex + maxInputSize))
            maxInputSize
        } else {
            UnsafeBufferOperations.writeToTail(outputBuffer, outputSize) { output, outputStartIndex, _ ->
                transformIntoByteArray(
                    source = input,
                    destination = output,
                    destinationOffset = outputStartIndex,
                    startIndex = inputStartIndex,
                    endIndex = inputStartIndex + inputSize
                )
            }
            inputSize
        }
    }

    @OptIn(UnsafeIoApi::class)
    private fun finalizeTo(outputBuffer: Buffer) {
        val maxOutputSize = maxOutputSize(0)
        if (maxOutputSize == 0) return

        if (maxOutputSize == -1 || maxOutputSize > UnsafeBufferOperations.maxSafeWriteCapacity) {
            outputBuffer.write(finalizeToByteArray())
        } else {
            UnsafeBufferOperations.writeToTail(outputBuffer, maxOutputSize) { output, outputStartIndex, _ ->
                finalizeIntoByteArray(output, outputStartIndex)
            }
        }
    }

    private inner class TransformedSource(private val source: RawSource) : RawSource {
        private var isFinalized: Boolean = false
        private var isClosed: Boolean = false

        private val inputBuffer = Buffer()
        private val outputBuffer = Buffer()

        override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
            require(byteCount >= 0) { "byteCount[$byteCount] < 0" }
            check(!isClosed) { "Already closed" }
            if (byteCount == 0L) return 0L

            while (outputBuffer.size == 0L && !isFinalized) {
                // TODO: what should be the value for readAtMostTo byteCount?
                @OptIn(UnsafeIoApi::class)
                val bytesRead = source.readAtMostTo(inputBuffer, UnsafeBufferOperations.maxSafeWriteCapacity.toLong())
                if (bytesRead == -1L) {
                    isFinalized = true
                    while (inputBuffer.size != 0L) {
                        transformTo(inputBuffer, outputBuffer, Long.MAX_VALUE)
                    }
                    finalizeTo(outputBuffer)
                } else {
                    transformTo(inputBuffer, outputBuffer, Long.MAX_VALUE)
                }
            }

            return outputBuffer.readAtMostTo(sink, byteCount)
        }

        override fun close() {
            if (isClosed) return
            isClosed = true

            inputBuffer.clear()
            outputBuffer.clear()

            var thrown = try {
                source.close()
                null
            } catch (cause: Throwable) {
                cause
            }

            try {
                this@BaseCipherFunction.close()
            } catch (cause: Throwable) {
                if (thrown == null) thrown = cause
                else thrown.addSuppressed(cause)
            }

            if (thrown != null) throw thrown
        }
    }

    private inner class TransformedSink(private val sink: RawSink) : RawSink {
        private var isClosed: Boolean = false

        private val outputBuffer = Buffer()

        override fun write(source: Buffer, byteCount: Long) {
            require(byteCount >= 0) { "byteCount[$byteCount] < 0" }
            check(!isClosed) { "Already closed" }

            var remaining = byteCount
            while (remaining > 0) {
                remaining -= transformTo(source, outputBuffer, remaining)
            }

            outputBuffer.transferTo(sink)
        }

        override fun flush() {
            sink.flush()
        }

        override fun close() {
            if (isClosed) return
            isClosed = true

            var thrown = try {
                finalizeTo(outputBuffer)
                outputBuffer.transferTo(sink)
                null
            } catch (cause: Throwable) {
                cause
            }

            outputBuffer.clear()

            try {
                sink.close()
            } catch (cause: Throwable) {
                if (thrown == null) thrown = cause
                else thrown.addSuppressed(cause)
            }

            try {
                this@BaseCipherFunction.close()
            } catch (cause: Throwable) {
                if (thrown == null) thrown = cause
                else thrown.addSuppressed(cause)
            }

            if (thrown != null) throw thrown
        }
    }
}

