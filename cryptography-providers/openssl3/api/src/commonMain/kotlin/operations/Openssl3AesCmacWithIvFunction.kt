package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.providers.base.checkBounds
import dev.whyoleg.cryptography.providers.base.operations.BaseCipherFunction
import dev.whyoleg.cryptography.providers.base.operations.CipherFunction
import dev.whyoleg.cryptography.providers.base.refToU
import dev.whyoleg.cryptography.providers.base.safeAddressOfU
import dev.whyoleg.cryptography.providers.openssl3.internal.Resource
import dev.whyoleg.cryptography.providers.openssl3.internal.SafeCloseAction
import dev.whyoleg.cryptography.providers.openssl3.internal.SafeCloseable
import dev.whyoleg.cryptography.providers.openssl3.internal.checkError
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER_CTX
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER_CTX_ctrl
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER_CTX_free
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER_CTX_get_block_size
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER_CTX_get_iv_length
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CIPHER_CTX_new
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CTRL_INIT
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CipherFinal
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CipherInit_ex2
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_CipherUpdate
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value

internal fun AES_CMAC_WITH_IV_CIPHER_CTX(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray?,
    ivStartIndex: Int,
    encrypt: Boolean,
    init: (CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): Resource<CPointer<EVP_CIPHER_CTX>?> {
    val context = checkError(EVP_CIPHER_CTX_new())
    val resource = Resource<CPointer<EVP_CIPHER_CTX>?>(context, ::EVP_CIPHER_CTX_free)
    try {
        checkError(
            EVP_CipherInit_ex2(
                ctx = context,
                cipher = cipher,
                key = key.refToU(0),
                iv = iv?.refToU(ivStartIndex),
                params = null,
                enc = if (encrypt) 1 else 0
            )
        )
        init(context)
    } catch (cause: Throwable) {
        resource.close()
        throw cause
    }
    return resource
}

internal fun AesCmacWithIvCipherFunction(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray,
    ivStartIndex: Int,
    encrypt: Boolean,
    init: (CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): CipherFunction {
    return AesCmacWithIvCipherFunction(AES_CMAC_WITH_IV_CIPHER_CTX(cipher, key, iv, ivStartIndex, encrypt, init))
}

@OptIn(ExperimentalStdlibApi::class)
internal open class AesCmacWithIvCipherFunction(
    protected val context: Resource<CPointer<EVP_CIPHER_CTX>?>,
) : BaseCipherFunction() {

    private lateinit var poly: ByteArray
    internal val iv: ByteArray = context.access().let { ctx ->
        val ivSize = EVP_CIPHER_CTX_get_iv_length(ctx)
        ByteArray(ivSize).also { ivArray ->
            checkError(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, ivArray.refToU(0)))
        }
    }
    private var k1 = ByteArray(16)
    private var k2 = ByteArray(16)
    private val buf = ByteArray(16)
    private var bufOff = 0
    private val mac = ByteArray(16)

    private val closeable = SafeCloseable(SafeCloseAction(context, AutoCloseable::close))
    override val blockSize: Int
        get() = checkError(EVP_CIPHER_CTX_get_block_size(context.access()))

    override fun initialize() {
        require(iv.size == blockSize) { "IV size must match block size" }

        poly = lookupPoly(blockSize)

        // Initialize zeroes array
        val zeroes = ByteArray(blockSize)

        // Process zeroes to compute L
        val l = ByteArray(blockSize)
        transformToByteArray(zeroes, 0, blockSize).copyInto(l, 0, 0, blockSize)

        // Compute k1 and k2
        k1 = doubleLu(l)
        k2 = doubleLu(k1)

        reset()
    }

    override fun maxOutputSize(inputSize: Int): Int {
        val blockSize = blockSize
        if (blockSize == 1) return inputSize
        return inputSize + blockSize
    }

    override fun process(input: ByteArray, iv: ByteArray): ByteArray {
        update(input, 0, input.size)

        val lu: ByteArray
        if (bufOff == blockSize) {
            lu = k1
        } else {
            addISO7816d4Padding(buf, bufOff)
            lu = k2
        }

        // XOR buffer with LU
        for (i in mac.indices) {
            buf[i] = (buf[i].toInt() xor lu[i].toInt()).toByte()
        }

        // XOR buffer with IV
        for (i in 0 until blockSize) {
            buf[i] = (buf[i].toInt() xor iv[i].toInt()).toByte()
        }

        // Process block
        transformToByteArray(buf, 0, blockSize).copyInto(mac, 0, 0, blockSize)

        // Update IV
        mac.copyInto(iv, 0, 0, iv.size)
        reset()

        return mac
    }

    override fun transform(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        update(source, startIndex, endIndex - startIndex)

        // Copy source into buffer
        source.copyInto(buf, destinationOffset = 0, startIndex = startIndex, endIndex = startIndex + bufOff)

        val lu: ByteArray
        if (bufOff == blockSize) {
            lu = k1
        } else {
            addISO7816d4Padding(buf, bufOff)
            lu = k2
        }

        // XOR buffer with LU
        for (i in mac.indices) {
            buf[i] = (buf[i].toInt() xor lu[i].toInt()).toByte()
        }

        // XOR buffer with IV
        for (i in 0 until blockSize) {
            buf[i] = (buf[i].toInt() xor iv[i].toInt()).toByte()
        }

        // Process block
        transformToByteArray(buf, 0, blockSize).copyInto(mac, 0, 0, blockSize)

        // Update IV
        mac.copyInto(iv, 0, 0, iv.size)
        reset()

        return mac
    }

    @OptIn(UnsafeNumber::class)
    override fun transformIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        checkBounds(source.size, startIndex, endIndex)
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(endIndex - startIndex))

        val context = context.access()
        val blockSize = blockSize // Ensure block size is retrieved from the cipher context

        return memScoped {
            val dataOutMoved = alloc<IntVar>()
            source.usePinned { sourcePinned ->
                destination.usePinned { destinationPinned ->
                    val inputLength = endIndex - startIndex
                    require(inputLength % blockSize == 0) { "Input length must be a multiple of the block size" }
                    checkError(
                        EVP_CipherUpdate(
                            ctx = context,
                            out = destinationPinned.safeAddressOfU(destinationOffset),
                            outl = dataOutMoved.ptr,
                            `in` = sourcePinned.safeAddressOfU(startIndex),
                            inl = inputLength.convert(),
                        )
                    )
                }
            }
            dataOutMoved.value.convert<Int>()
        }
    }

    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(0))

        val context = context.access()

        return memScoped {
            val dataOutMoved = alloc<IntVar>()
            destination.usePinned { destinationPinned ->
                checkError(
                    EVP_CipherFinal(
                        ctx = context,
                        outm = destinationPinned.safeAddressOfU(destinationOffset),
                        outl = dataOutMoved.ptr
                    )
                )
            }
            dataOutMoved.value.convert()
        }
    }

    override fun close() {
        closeable.close()
    }

    fun reset() {/*
         * clean the buffer.
         */
        for (i in buf.indices) {
            buf[i] = 0
        }

        bufOff = 0

        // reset the underlying cipher
        resetCipher(context.access(), iv, iv.copyOf(iv.size))
    }

    fun resetCipher(context: CPointer<EVP_CIPHER_CTX>?, iv: ByteArray, originalIv: ByteArray) {
        // Reset the IV to the original value
        originalIv.copyInto(iv, 0, 0, originalIv.size)
        // Clear any intermediate buffers (if applicable)
        iv.fill(0)

        // Reinitialize the cipher context with the original IV
        checkError(
            EVP_CipherInit_ex2(
                ctx = context,
                cipher = null, // Reuse the existing cipher
                key = null,    // Reuse the existing key
                iv = iv.refToU(0),
                params = null,
                enc = -1       // Reuse the current encryption/decryption mode
            )
        )
    }

    private fun update(input: ByteArray, inputOffset: Int, length: Int) {
        var inOff = inputOffset
        var len = length
        require(len >= 0) { "Can't have a negative input length!" }

        val blockSize = buf.size
        val gapLen = blockSize - bufOff

        if (len > gapLen) {
            input.copyInto(buf, bufOff, inOff, inOff + gapLen)

            super.transform(buf, 0, blockSize).copyInto(mac, 0, 0, blockSize)

            bufOff = 0
            len -= gapLen
            inOff += gapLen

            while (len > blockSize) {
                super.transform(input, inOff, inOff + blockSize).copyInto(mac, 0, 0, blockSize)

                len -= blockSize
                inOff += blockSize
            }
        }

        input.copyInto(buf, bufOff, inOff, inOff + len)

        bufOff += len
    }

    private fun addISO7816d4Padding(buffer: ByteArray, offset: Int) {
        buffer[offset] = 0x80.toByte() // Add the 0x80 byte
        for (i in offset + 1 until buffer.size) {
            buffer[i] = 0x00 // Fill the rest with 0x00
        }
    }

    private fun doubleLu(input: ByteArray): ByteArray {
        val ret = ByteArray(input.size)
        val carry = shiftLeft(input, ret)

        /*
         * NOTE: This construction is an attempt at a constant-time implementation.
         */
        val mask = (-carry) and 0xff
        ret[input.size - 3] = (ret[input.size - 3].toInt() xor (poly[1].toInt() and mask)).toByte()
        ret[input.size - 2] = (ret[input.size - 2].toInt() xor (poly[2].toInt() and mask)).toByte()
        ret[input.size - 1] = (ret[input.size - 1].toInt() xor (poly[3].toInt() and mask)).toByte()
        return ret
    }

    private fun shiftLeft(block: ByteArray, output: ByteArray): Int {
        var i = block.size
        var bit = 0
        while (--i >= 0) {
            val b = block[i].toInt() and 0xff
            output[i] = ((b shl 1) or bit).toByte()
            bit = (b ushr 7) and 1
        }
        return bit
    }

    private fun lookupPoly(blockSizeLength: Int): ByteArray {
        val xor = when (blockSizeLength * 8) {
            64   -> 0x1B
            128  -> 0x87
            160  -> 0x2D
            192  -> 0x87
            224  -> 0x309
            256  -> 0x425
            320  -> 0x1B
            384  -> 0x100D
            448  -> 0x851
            512  -> 0x125
            768  -> 0xA0011
            1024 -> 0x80043
            2048 -> 0x86001
            else -> throw IllegalArgumentException("Unknown block size for CMAC: " + (blockSizeLength * 8))
        }
        return intToBigEndian(xor)
    }

    private fun intToBigEndian(value: Int): ByteArray {
        return byteArrayOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte()
        )
    }
}
