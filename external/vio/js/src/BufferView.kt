package dev.whyoleg.vio

import org.khronos.webgl.*

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
    public val arrayBufferView: ArrayBufferView,
    override var readIndex: Int = 0,
    override var writeIndex: Int = 0
) : BufferView() {
    override val size: Int
        get() = arrayBufferView.byteLength - arrayBufferView.byteOffset
}

public fun ArrayBufferView.view(
    readIndex: Int = 0,
    writeIndex: Int = 0
): PlatformBufferView = PlatformBufferView(this, readIndex, writeIndex)
