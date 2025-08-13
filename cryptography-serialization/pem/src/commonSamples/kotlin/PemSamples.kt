/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.test.*

class PemSamples {
    @Test
    fun encodeToString() {
        val document = PemDocument(
            label = PemLabel("CUSTOM"),
            content = "hello world".encodeToByteString(),
        )

        val encoded = document.encodeToString()

        assertEquals(
            expected = """
            -----BEGIN CUSTOM-----
            aGVsbG8gd29ybGQ=
            -----END CUSTOM-----
            
            """.trimIndent(),
            actual = encoded
        )
    }

    @Test
    fun encodeToByteArray() {
        val document = PemDocument(
            label = PemLabel("CUSTOM"),
            content = "hello world".encodeToByteString(),
        )

        val encoded = document.encodeToByteArray()

        assertContentEquals(
            expected = """
            -----BEGIN CUSTOM-----
            aGVsbG8gd29ybGQ=
            -----END CUSTOM-----
            
            """.trimIndent().encodeToByteArray(),
            actual = encoded
        )
    }

    @Test
    fun encodeToByteString() {
        val document = PemDocument(
            label = PemLabel("CUSTOM"),
            content = "hello world".encodeToByteString(),
        )

        val encoded = document.encodeToByteString()

        assertEquals(
            expected = """
            -----BEGIN CUSTOM-----
            aGVsbG8gd29ybGQ=
            -----END CUSTOM-----
            
            """.trimIndent().encodeToByteString(),
            actual = encoded
        )
    }

    @Test
    fun encodeToSink() {
        val document = PemDocument(
            label = PemLabel("CUSTOM"),
            content = "hello world".encodeToByteString(),
        )

        val buffer = Buffer()
        document.encodeToSink(buffer)
        val encoded = buffer.readString()

        assertEquals(
            expected = """
            -----BEGIN CUSTOM-----
            aGVsbG8gd29ybGQ=
            -----END CUSTOM-----
            
            """.trimIndent(),
            actual = encoded
        )
    }

    @Test
    fun decodeFromString() {
        val pem: String = """
        -----BEGIN CUSTOM-----
        aGVsbG8gd29ybGQ=
        -----END CUSTOM-----
        
        """.trimIndent()

        val document = PemDocument.decode(pem)

        assertEquals(
            expected = PemDocument(
                label = PemLabel("CUSTOM"),
                content = "hello world".encodeToByteString()
            ),
            actual = document
        )
    }

    @Test
    fun decodeFromByteArray() {
        val pem: ByteArray = """
        -----BEGIN CUSTOM-----
        aGVsbG8gd29ybGQ=
        -----END CUSTOM-----
        
        """.trimIndent().encodeToByteArray()

        val document = PemDocument.decode(pem)

        assertEquals(
            expected = PemDocument(
                label = PemLabel("CUSTOM"),
                content = "hello world".encodeToByteString()
            ),
            actual = document
        )
    }

    @Test
    fun decodeFromByteString() {
        val pem: ByteString = """
        -----BEGIN CUSTOM-----
        aGVsbG8gd29ybGQ=
        -----END CUSTOM-----
        
        """.trimIndent().encodeToByteString()

        val document = PemDocument.decode(pem)

        assertEquals(
            expected = PemDocument(
                label = PemLabel("CUSTOM"),
                content = "hello world".encodeToByteString()
            ),
            actual = document
        )
    }

    @Test
    fun decodeFromSource() {
        val pem = """
        -----BEGIN CUSTOM-----
        aGVsbG8gd29ybGQ=
        -----END CUSTOM-----
        
        """.trimIndent()

        val buffer = Buffer()
        buffer.writeString(pem)

        val document = PemDocument.decode(buffer)

        assertEquals(
            expected = PemDocument(
                label = PemLabel("CUSTOM"),
                content = "hello world".encodeToByteString()
            ),
            actual = document
        )
    }

    @Test
    fun decodeToSequenceFromString() {
        val pem: String = """
        -----BEGIN A-----
        YQ==
        -----END A-----
        
        -----BEGIN B-----
        Yg==
        -----END B-----
        
        """.trimIndent()

        val documents = PemDocument.decodeToSequence(pem).toList()

        assertEquals(
            expected = listOf(
                PemDocument(PemLabel("A"), "a".encodeToByteString()),
                PemDocument(PemLabel("B"), "b".encodeToByteString()),
            ),
            actual = documents,
        )
    }

    @Test
    fun decodeToSequenceFromByteArray() {
        val pem: ByteArray = """
        -----BEGIN A-----
        YQ==
        -----END A-----
        
        -----BEGIN B-----
        Yg==
        -----END B-----
        
        """.trimIndent().encodeToByteArray()

        val documents = PemDocument.decodeToSequence(pem).toList()

        assertEquals(
            expected = listOf(
                PemDocument(PemLabel("A"), "a".encodeToByteString()),
                PemDocument(PemLabel("B"), "b".encodeToByteString()),
            ),
            actual = documents,
        )
    }

    @Test
    fun decodeToSequenceFromByteString() {
        val pem: ByteString = """
        -----BEGIN A-----
        YQ==
        -----END A-----
        
        -----BEGIN B-----
        Yg==
        -----END B-----
        
        """.trimIndent().encodeToByteString()

        val documents = PemDocument.decodeToSequence(pem).toList()

        assertEquals(
            expected = listOf(
                PemDocument(PemLabel("A"), "a".encodeToByteString()),
                PemDocument(PemLabel("B"), "b".encodeToByteString()),
            ),
            actual = documents,
        )
    }

    @Test
    fun decodeToSequenceFromSource() {
        val pem = """
        -----BEGIN A-----
        YQ==
        -----END A-----
        
        -----BEGIN B-----
        Yg==
        -----END B-----
        
        """.trimIndent()

        val buffer = Buffer()
        buffer.writeString(pem)

        val documents = PemDocument.decodeToSequence(buffer).toList()

        assertEquals(
            expected = listOf(
                PemDocument(PemLabel("A"), "a".encodeToByteString()),
                PemDocument(PemLabel("B"), "b".encodeToByteString()),
            ),
            actual = documents,
        )
    }
}
