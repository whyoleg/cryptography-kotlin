/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.test.*

class PemTest {

    @Test
    fun testHelloWorld() = testPem(
        label = "UNKNOWN",
        content = "Hello World".encodeToByteString(),
        document = """
        -----BEGIN UNKNOWN-----
        SGVsbG8gV29ybGQ=
        -----END UNKNOWN-----
        """.trimIndent()
    )

    @Test
    fun testMultiLine() = testPem(
        label = "UNKNOWN CHUNKED",
        content = "Hello World".repeat(10).encodeToByteString(),
        document = """
        -----BEGIN UNKNOWN CHUNKED-----
        SGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxs
        byBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdv
        cmxkSGVsbG8gV29ybGQ=
        -----END UNKNOWN CHUNKED-----
        """.trimIndent()
    )

    @Test
    fun testDecodingWithComment() = testPemDecode(
        label = "UNKNOWN",
        content = "Hello World".encodeToByteString(),
        // because of comments we test only if's decoded correctly
        document = """
        Here is some description for pem
        it should not affect anything
        -----BEGIN UNKNOWN-----
        SGVsbG8gV29ybGQ=
        -----END UNKNOWN-----
        Here is some comments in the end
        """
    )

    @Test
    fun testDecodingWithNoBeginLabel() = testPemDecodeFailure(
        document = "SGVsbG8gV29ybGQ=\n-----END UNKNOWN-----"
    ) {
        assertIs<IllegalArgumentException>(it)
        assertEquals("Invalid PEM format: missing BEGIN label", it.message)
    }

    @Test
    fun testDecodingWithNoEndLabel() = testPemDecodeFailure(
        document = "-----BEGIN UNKNOWN-----\nSGVsbG8gV29ybGQ="
    ) {
        assertIs<IllegalArgumentException>(it)
        assertEquals("Invalid PEM format: missing END label", it.message)
    }

    @Test
    fun testDecodingWithDifferentLabels() = testPemDecodeFailure(
        document = """
        -----BEGIN UNKNOWN1-----
        SGVsbG8gV29ybGQ=
        -----END UNKNOWN2-----
        """.trimIndent()
    ) {
        assertIs<IllegalArgumentException>(it)
        assertEquals("Invalid PEM format: BEGIN(UNKNOWN1) and END(UNKNOWN2) labels mismatch", it.message)
    }

    private fun testPem(
        label: String,
        content: ByteString,
        document: String,
    ) {
        testPemDecode(label, content, document)
        testPemEncode(label, content, document)
    }

    private fun testPemDecode(
        label: String,
        content: ByteString,
        document: String,
    ) {
        val expectedDocument = PemDocument(PemLabel(label), content)

        assertEquals(expectedDocument, PemDocument.decode(document))
        assertEquals(expectedDocument, PemDocument.decode(document.encodeToByteString()))
        assertEquals(expectedDocument, PemDocument.decode(document.encodeToByteArray()))
        assertEquals(expectedDocument, PemDocument.decode(Buffer().also {
            it.write(document.encodeToByteArray())
        }))
        assertEquals(expectedDocument, PemDocument.decode((Buffer().also {
            it.write(document.encodeToByteArray())
        } as Source).buffered()))
    }

    private fun testPemDecodeFailure(
        document: String,
        assertThrowable: (Throwable) -> Unit,
    ) {
        assertThrowable(assertFails { PemDocument.decode(document) })
        assertThrowable(assertFails { PemDocument.decode(document.encodeToByteString()) })
        assertThrowable(assertFails { PemDocument.decode(document.encodeToByteArray()) })
        assertThrowable(assertFails {
            PemDocument.decode(Buffer().also {
                it.write(document.encodeToByteArray())
            })
        })
        assertThrowable(assertFails {
            PemDocument.decode((Buffer().also {
                it.write(document.encodeToByteArray())
            } as Source).buffered())
        })
    }

    private fun testPemEncode(
        label: String,
        content: ByteString,
        document: String,
    ) {
        val expectedDocument = PemDocument(PemLabel(label), content)

        assertLinesEquals(document, expectedDocument.encodeToString())
        assertLinesEquals(document, expectedDocument.encodeToByteArray().decodeToString())
        assertLinesEquals(document, expectedDocument.encodeToByteString().decodeToString())
        assertLinesEquals(document, Buffer().also {
            expectedDocument.encodeToSink(it)
        }.readString())
        assertLinesEquals(document, Buffer().also {
            val sink = (it as Sink).buffered()
            expectedDocument.encodeToSink(sink)
            sink.flush()
        }.readString())
    }

    private fun assertLinesEquals(expected: String, actual: String) {
        assertEquals(
            expected.lines().dropLastWhile { it.isBlank() },
            actual.lines().dropLastWhile { it.isBlank() },
        )
    }
}
