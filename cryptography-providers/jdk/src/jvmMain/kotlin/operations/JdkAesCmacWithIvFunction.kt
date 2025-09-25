package dev.whyoleg.cryptography.providers.jdk.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.checkBounds
import dev.whyoleg.cryptography.providers.base.operations.BaseCipherFunction
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.IvParameterSpec

internal class JdkAesCmacWithIvCipher(
    val state: JdkCryptographyState,
    val key: JSecretKey,
    val ivSize: Int,
    val algorithm: String,
) : AesCmacWithIvCipher {
    lateinit var cipherFunction: JdkAesCmacWithIvFunction

    @OptIn(ExperimentalStdlibApi::class)
    override fun initialize() {
        cipherFunction = JdkAesCmacWithIvFunction(algorithm = algorithm, key = key, state = state)
        cipherFunction.initialize()
    }

    @DelicateCryptographyApi
    override fun processBlocking(input: ByteArray, iv: ByteArray): ByteArray = cipherFunction.process(input, iv)

    @DelicateCryptographyApi
    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray = cipherFunction.transform(plaintext)
}

@OptIn(CryptographyProviderApi::class)
@CryptographyProviderApi
internal open class JdkAesCmacWithIvFunction(
    state: JdkCryptographyState,
    private val key: JSecretKey,
    algorithm: String,
) : BaseCipherFunction() {

    private lateinit var poly: ByteArray
    internal val iv: ByteArray = ByteArray(16) // AES block size
    private var k1 = ByteArray(16)
    private var k2 = ByteArray(16)
    private val buf = ByteArray(16)
    private var bufOff = 0
    private val mac = ByteArray(16)
    private val cipherPool = state.cipher(algorithm)

    @CryptographyProviderApi
    override val blockSize: Int = iv.size

    @OptIn(ExperimentalStdlibApi::class)
    @CryptographyProviderApi
    override fun initialize() {
        require(iv.size == blockSize) { "IV size must match block size" }
        poly = lookupPoly(blockSize)
        val zeroes = ByteArray(blockSize)
        val l = ByteArray(blockSize)
        transformToByteArray(zeroes, 0, blockSize).copyInto(l, 0, 0, blockSize)
        k1 = doubleLu(l)
        k2 = doubleLu(k1)
        reset()
    }

    @CryptographyProviderApi
    override fun maxOutputSize(inputSize: Int): Int {
        val blockSize = blockSize
        if (blockSize == 1) return inputSize
        return inputSize + blockSize
    }

    @CryptographyProviderApi
    override fun close() {
    }

    @OptIn(ExperimentalStdlibApi::class)
    @CryptographyProviderApi
    override fun transform(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        update(source, startIndex, endIndex - startIndex)
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

    @CryptographyProviderApi
    override fun transformIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        checkBounds(source.size, startIndex, endIndex)
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(endIndex - startIndex))

        val inputLength = endIndex - startIndex
        require(inputLength % blockSize == 0) { "Input length must be a multiple of the block size" }

        // Use the underlying cipher to perform the actual transformation
        return cipherPool.use { cipherInstance ->
            cipherInstance.init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
            cipherInstance.update(
                source, // input
                startIndex, // inputOffset
                inputLength, // inputLen
                destination, // output
                destinationOffset // outputOffset
            )
        }
    }

    @CryptographyProviderApi
    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(0))

        // Use the underlying cipher to perform the final transformation
        return cipherPool.use { cipherInstance ->
            cipherInstance.init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
            cipherInstance.doFinal(
                destination, // output
                destinationOffset // outputOffset
            )
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
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

    @OptIn(ExperimentalStdlibApi::class)
    @CryptographyProviderApi
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

    fun reset() {/*
         * clean the buffer.
         */
        for (i in buf.indices) {
            buf[i] = 0
        }

        bufOff = 0

        // reset the underlying cipher
        resetCipher(iv, iv.copyOf(iv.size))
    }

    fun resetCipher(iv: ByteArray, originalIv: ByteArray) {
        // Reset the IV to the original value
        originalIv.copyInto(iv, 0, 0, originalIv.size)
        // Clear any intermediate buffers (if applicable)
        iv.fill(0)
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