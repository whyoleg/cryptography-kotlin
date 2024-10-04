/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import kotlinx.io.*

@CryptographyProviderApi
public class BaseAesImplicitIvEncryptFunction(
    private val iv: ByteArray,
    private val cipherFunction: CipherFunction,
) : CipherFunction {
    override fun transform(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        return iv + cipherFunction.transform(source, startIndex, endIndex)
    }

    override fun transformedSource(source: RawSource): RawSource {
        return ImplicitIvSource(iv, cipherFunction.transformedSource(source))
    }

    override fun transformedSink(sink: RawSink): RawSink {
        return cipherFunction.transformedSink(ImplicitIvSink(iv, sink))
    }

    private class ImplicitIvSource(
        iv: ByteArray,
        private val transformedSource: RawSource,
    ) : RawSource {
        // TODO: optimize by just using ByteArray
        private val iv = Buffer().apply { write(iv) }
        override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
            require(byteCount >= 0L) { "byteCount < 0: $byteCount" }
            if (byteCount == 0L) return 0L

            // first write IV
            val remaining = if (iv.size != 0L) {
                val bytesWritten = iv.readAtMostTo(sink, byteCount)
                // if not full IV is written - early return moved
                if (iv.size != 0L) return bytesWritten
                byteCount - bytesWritten
            } else byteCount

            return transformedSource.readAtMostTo(sink, remaining)
        }

        override fun close() {
            transformedSource.close()
        }
    }

    private class ImplicitIvSink(
        iv: ByteArray,
        private val originalSink: RawSink,
    ) : RawSink {
        // TODO: optimize by just using ByteArray
        private val iv = Buffer().apply { write(iv) }
        override fun write(source: Buffer, byteCount: Long) {
            source.require(byteCount)
            if (byteCount == 0L) return

            // first write IV
            if (iv.size != 0L) {
                originalSink.write(iv, iv.size)
            }

            originalSink.write(source, byteCount)
        }

        override fun flush() {
            originalSink.flush()
        }

        override fun close() {
            originalSink.close()
        }
    }
}

@CryptographyProviderApi
public class BaseAesImplicitIvDecryptFunction(
    private val ivSize: Int,
    private val initialize: (iv: ByteArray, startIndex: Int) -> CipherFunction,
) : CipherFunction {
    override fun transform(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        checkBounds(source.size, startIndex, endIndex)
        require(endIndex - startIndex >= ivSize) { "Not enough data to read iv" }
        return initialize(source, startIndex).transform(source, startIndex + ivSize, endIndex)
    }

    override fun transformedSource(source: RawSource): RawSource {
        return ImplicitIvSource(source)
    }

    override fun transformedSink(sink: RawSink): RawSink {
        return ImplicitIvSink(sink)
    }

    private inner class ImplicitIvSource(
        private val originalSource: RawSource,
    ) : RawSource {
        private var transformedSource: RawSource? = null
        override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
            require(byteCount >= 0L) { "byteCount < 0: $byteCount" }
            if (byteCount == 0L) return 0L

            // initialize
            if (transformedSource == null) {
                val ivBuffer = Buffer()
                ivBuffer.write(originalSource, ivSize.toLong())
                // TODO: optimize by removing readByteArray
                transformedSource = initialize(ivBuffer.readByteArray(), 0).transformedSource(originalSource)
            }

            return transformedSource!!.readAtMostTo(sink, byteCount)
        }

        override fun close() {
            transformedSource?.close() ?: originalSource.close()
        }
    }

    private inner class ImplicitIvSink(
        private val originalSink: RawSink,
    ) : RawSink {
        private var transformedSink: RawSink? = null
        private val ivBuffer = Buffer()
        override fun write(source: Buffer, byteCount: Long) {
            source.require(byteCount)
            if (byteCount == 0L) return

            // initialize
            val remaining = if (transformedSink == null) {
                val bytesWritten = source.readAtMostTo(ivBuffer, minOf(byteCount, ivSize.toLong() - ivBuffer.size))
                if (ivBuffer.size != ivSize.toLong()) return
                // TODO: optimize by removing readByteArray
                transformedSink = initialize(ivBuffer.readByteArray(), 0).transformedSink(originalSink)
                byteCount - bytesWritten
            } else byteCount

            transformedSink!!.write(source, remaining)
        }

        override fun flush() {
            transformedSink?.flush()
        }

        override fun close() {
            transformedSink?.close() ?: originalSink.close()
        }
    }
}
