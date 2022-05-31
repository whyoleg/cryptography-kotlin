package dev.whyoleg.vio

import java.nio.*

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

public actual class PlatformBufferView(
    public val byteBuffer: ByteBuffer
) : BufferView() {
    override val size: Int
        get() = byteBuffer.capacity()

    override var readIndex: Int
        get() = byteBuffer.position()
        set(value) {
            byteBuffer.position(value)
        }

    override var writeIndex: Int
        get() = byteBuffer.limit()
        set(value) {
            byteBuffer.limit(value)
        }

}

public fun ByteBuffer.view(): PlatformBufferView = PlatformBufferView(this)
