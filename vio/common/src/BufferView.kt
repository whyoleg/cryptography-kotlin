package dev.whyoleg.vio

public expect sealed class BufferView {
    public abstract var readIndex: Int
    public abstract var writeIndex: Int
    public abstract val size: Int

    public companion object {
        public val Empty: BufferView
    }
}

public fun BufferView.readRemaining(): Int = writeIndex - readIndex
public fun BufferView.writeRemaining(): Int = size - writeIndex

public fun BufferView.canRead(): Boolean = readRemaining() > 0
public fun BufferView.canWrite(): Boolean = writeRemaining() > 0

public fun BufferView.reset() {
    readIndex = 0
    writeIndex = 0
}

public expect class ByteArrayBufferView(
    array: ByteArray,
    arrayOffset: Int = 0,
    arraySize: Int = array.size,
    readIndex: Int = 0,
    writeIndex: Int = 0
) : BufferView {
    public val array: ByteArray
    public val arrayOffset: Int
    public val arraySize: Int
}

//TODO: name? view? bufferView? etc
public fun ByteArray.view(
    arrayOffset: Int = 0,
    arraySize: Int = this.size,
    readIndex: Int = 0,
    writeIndex: Int = 0
): ByteArrayBufferView = ByteArrayBufferView(this, arrayOffset, arraySize, readIndex, writeIndex)

public expect class PlatformBufferView : BufferView
