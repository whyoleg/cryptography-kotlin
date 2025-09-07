/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlin.test.*

class ListEncodingTest {
    private fun ByteArray.toHex() = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    @Test
    fun encode_sequenceOf_int_topLevel() {
        val list = listOf(1, 2, 3)
        val bytes = Der.encodeToByteArray(ListSerializer(Int.serializer()), list)
        assertEquals("3009020101020102020103", bytes.toHex())
    }

    @Test
    fun encode_sequenceOf_int_empty() {
        val list = emptyList<Int>()
        val bytes = Der.encodeToByteArray(ListSerializer(Int.serializer()), list)
        assertEquals("3000", bytes.toHex())
    }

    @Test
    fun decode_sequenceOf_int_topLevel() {
        val bytes = "3009020101020102020103".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val list = Der.decodeFromByteArray(ListSerializer(Int.serializer()), bytes)
        assertEquals(listOf(1, 2, 3), list)
    }
}
