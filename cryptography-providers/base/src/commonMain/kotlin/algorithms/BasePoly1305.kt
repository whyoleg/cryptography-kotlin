/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*

@OptIn(DelicateCryptographyApi::class, CryptographyProviderApi::class)
public object BasePoly1305 : Poly1305 {
    override fun keyDecoder(): KeyDecoder<Poly1305.Key.Format, Poly1305.Key> = Poly1305KeyDecoder

    private object Poly1305KeyDecoder : KeyDecoder<Poly1305.Key.Format, Poly1305.Key> {
        override fun decodeFromByteArrayBlocking(format: Poly1305.Key.Format, bytes: ByteArray): Poly1305.Key {
            require(bytes.size == Poly1305.KEY_SIZE) { "Poly1305 key must be 32 bytes" }
            return when (format) {
                Poly1305.Key.Format.RAW -> Poly1305Key(bytes.copyOf())
            }
        }
    }
}

@OptIn(DelicateCryptographyApi::class, CryptographyProviderApi::class)
private class Poly1305Key(private val key: ByteArray) : Poly1305.Key {
    override fun encodeToByteArrayBlocking(format: Poly1305.Key.Format): ByteArray = when (format) {
        Poly1305.Key.Format.RAW -> key.copyOf()
    }

    override fun signatureGenerator(): SignatureGenerator = Poly1305SignatureGenerator(key)
    override fun signatureVerifier(): SignatureVerifier = Poly1305SignatureVerifier(key)
}

@OptIn(CryptographyProviderApi::class)
private class Poly1305SignatureGenerator(private val key: ByteArray) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = AccumulatingSignFunction { data ->
        Poly1305Engine.compute(key, data)
    }

    override fun generateSignatureBlocking(data: ByteArray): ByteArray {
        return Poly1305Engine.compute(key, data)
    }
}

@OptIn(DelicateCryptographyApi::class, CryptographyProviderApi::class)
private class Poly1305SignatureVerifier(private val key: ByteArray) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = AccumulatingVerifyFunction { data, signature ->
        if (signature.size != Poly1305.TAG_SIZE) return@AccumulatingVerifyFunction "Invalid signature size"
        val computed = Poly1305Engine.compute(key, data)
        if (constantTimeEquals(computed, signature)) null else "Signature mismatch"
    }

    override fun tryVerifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != Poly1305.TAG_SIZE) return false
        val computed = Poly1305Engine.compute(key, data)
        return constantTimeEquals(computed, signature)
    }
}

private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var result = 0
    for (i in a.indices) {
        result = result or (a[i].toInt() xor b[i].toInt())
    }
    return result == 0
}

/**
 * Poly1305 MAC implementation (RFC 8439).
 * Uses 5 x 26-bit limbs for accumulator representation.
 * Based on poly1305-donna reference implementation.
 */
internal object Poly1305Engine {
    private const val BLOCK_SIZE = 16

    fun compute(key: ByteArray, message: ByteArray): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }

        // Load r (first 16 bytes) and apply clamping to raw bytes
        // Clamping: clear top 4 bits of bytes 3,7,11,15 and bottom 2 bits of bytes 4,8,12
        val t0 = ((loadLE32(key, 0).toLong() and 0xFFFFFFFFL) and 0x0FFFFFFFL)  // clamp byte 3
        val t1 = ((loadLE32(key, 4).toLong() and 0xFFFFFFFFL) and 0x0FFFFFFCL)  // clamp bytes 4,7
        val t2 = ((loadLE32(key, 8).toLong() and 0xFFFFFFFFL) and 0x0FFFFFFCL)  // clamp bytes 8,11
        val t3 = ((loadLE32(key, 12).toLong() and 0xFFFFFFFFL) and 0x0FFFFFFCL) // clamp bytes 12,15

        // Convert to 26-bit limbs
        val r0 = t0 and 0x3FFFFFFL
        val r1 = ((t0 shr 26) or (t1 shl 6)) and 0x3FFFFFFL
        val r2 = ((t1 shr 20) or (t2 shl 12)) and 0x3FFFFFFL
        val r3 = ((t2 shr 14) or (t3 shl 18)) and 0x3FFFFFFL
        val r4 = (t3 shr 8) and 0x3FFFFFFL

        // Precompute 5*r for modular reduction
        val s1 = r1 * 5
        val s2 = r2 * 5
        val s3 = r3 * 5
        val s4 = r4 * 5

        // Accumulator h = 0
        var h0 = 0L
        var h1 = 0L
        var h2 = 0L
        var h3 = 0L
        var h4 = 0L

        // Process each 16-byte block
        var offset = 0
        while (offset < message.size) {
            val remaining = message.size - offset
            val blockLen = minOf(BLOCK_SIZE, remaining)

            // Create padded block
            val block = ByteArray(17)
            message.copyInto(block, 0, offset, offset + blockLen)
            block[blockLen] = 1  // Append 0x01 byte

            // Load block as little-endian
            val m0 = loadLE32(block, 0).toLong() and 0xFFFFFFFFL
            val m1 = loadLE32(block, 4).toLong() and 0xFFFFFFFFL
            val m2 = loadLE32(block, 8).toLong() and 0xFFFFFFFFL
            val m3 = loadLE32(block, 12).toLong() and 0xFFFFFFFFL
            val m4 = block[16].toLong() and 0xFFL

            // Convert to 26-bit limbs and add to accumulator
            h0 += (m0 and 0x3FFFFFFL)
            h1 += ((m0 shr 26) or (m1 shl 6)) and 0x3FFFFFFL
            h2 += ((m1 shr 20) or (m2 shl 12)) and 0x3FFFFFFL
            h3 += ((m2 shr 14) or (m3 shl 18)) and 0x3FFFFFFL
            h4 += (m3 shr 8) or (m4 shl 24)

            // h = (h * r) mod (2^130 - 5)
            // Schoolbook multiplication with reduction
            val d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
            var d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
            var d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
            var d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
            var d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0

            // Carry propagation
            var c: Long = d0 shr 26; h0 = d0 and 0x3FFFFFFL
            d1 += c; c = d1 shr 26; h1 = d1 and 0x3FFFFFFL
            d2 += c; c = d2 shr 26; h2 = d2 and 0x3FFFFFFL
            d3 += c; c = d3 shr 26; h3 = d3 and 0x3FFFFFFL
            d4 += c; c = d4 shr 26; h4 = d4 and 0x3FFFFFFL
            h0 += c * 5; c = h0 shr 26; h0 = h0 and 0x3FFFFFFL
            h1 += c

            offset += blockLen
        }

        // Final carry propagation
        var c = h1 shr 26; h1 = h1 and 0x3FFFFFFL
        h2 += c; c = h2 shr 26; h2 = h2 and 0x3FFFFFFL
        h3 += c; c = h3 shr 26; h3 = h3 and 0x3FFFFFFL
        h4 += c; c = h4 shr 26; h4 = h4 and 0x3FFFFFFL
        h0 += c * 5; c = h0 shr 26; h0 = h0 and 0x3FFFFFFL
        h1 += c

        // Compute h - p to check if h >= p
        var g0 = h0 + 5; c = g0 shr 26; g0 = g0 and 0x3FFFFFFL
        var g1 = h1 + c; c = g1 shr 26; g1 = g1 and 0x3FFFFFFL
        var g2 = h2 + c; c = g2 shr 26; g2 = g2 and 0x3FFFFFFL
        var g3 = h3 + c; c = g3 shr 26; g3 = g3 and 0x3FFFFFFL
        val g4 = h4 + c - (1L shl 26)

        // Select h if h < p, or g (= h - p) if h >= p
        val mask = g4 shr 63  // 0 if g4 >= 0, -1 if g4 < 0
        h0 = (h0 and mask) or (g0 and mask.inv())
        h1 = (h1 and mask) or (g1 and mask.inv())
        h2 = (h2 and mask) or (g2 and mask.inv())
        h3 = (h3 and mask) or (g3 and mask.inv())
        h4 = (h4 and mask) or (g4 and mask.inv())

        // Pack h from 26-bit limbs into 32-bit words
        val f0 = (h0 or (h1 shl 26)) and 0xFFFFFFFFL
        val f1 = ((h1 shr 6) or (h2 shl 20)) and 0xFFFFFFFFL
        val f2 = ((h2 shr 12) or (h3 shl 14)) and 0xFFFFFFFFL
        val f3 = ((h3 shr 18) or (h4 shl 8)) and 0xFFFFFFFFL

        // Add s (key[16..31])
        val s0 = loadLE32(key, 16).toLong() and 0xFFFFFFFFL
        val s1l = loadLE32(key, 20).toLong() and 0xFFFFFFFFL
        val s2l = loadLE32(key, 24).toLong() and 0xFFFFFFFFL
        val s3l = loadLE32(key, 28).toLong() and 0xFFFFFFFFL

        var carry: Long = f0 + s0
        val out0 = carry and 0xFFFFFFFFL
        carry = (carry shr 32) + f1 + s1l
        val out1 = carry and 0xFFFFFFFFL
        carry = (carry shr 32) + f2 + s2l
        val out2 = carry and 0xFFFFFFFFL
        carry = (carry shr 32) + f3 + s3l
        val out3 = carry and 0xFFFFFFFFL

        // Output tag
        val tag = ByteArray(16)
        storeLE32(tag, 0, out0.toInt())
        storeLE32(tag, 4, out1.toInt())
        storeLE32(tag, 8, out2.toInt())
        storeLE32(tag, 12, out3.toInt())

        return tag
    }

    private fun loadLE32(bytes: ByteArray, offset: Int): Int {
        return (bytes[offset].toInt() and 0xFF) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun storeLE32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value shr 8).toByte()
        bytes[offset + 2] = (value shr 16).toByte()
        bytes[offset + 3] = (value shr 24).toByte()
    }
}
