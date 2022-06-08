package dev.whyoleg.vio

import kotlinx.cinterop.*

public actual sealed class BufferView {
    public actual abstract var readIndex: Int
    public actual abstract var writeIndex: Int
    public actual abstract val size: Int

    public actual companion object {
        public actual val Empty: BufferView = ByteArrayBufferView(ByteArray(0))
    }
}

public actual class ByteArrayBufferView actual constructor(
    public actual val array: ByteArray,
    public actual val arrayOffset: Int,
    public actual val arraySize: Int,
    public override var readIndex: Int,
    public override var writeIndex: Int
) : BufferView() {
    override val size: Int
        get() = arraySize - arrayOffset
}

public class PlatformBufferView(
    public val pointer: CPointer<ByteVar>,
    override val size: Int,
    override var readIndex: Int = 0,
    override var writeIndex: Int = 0
) : BufferView()

public fun CPointer<ByteVar>.view(
    size: Int,
    readIndex: Int = 0,
    writeIndex: Int = 0
): PlatformBufferView = PlatformBufferView(this, size, readIndex, writeIndex)
