/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.test.*

class PemTest {

    @Test
    fun testByteArrayConstructorImmutability() {
        val content = byteArrayOf(1, 2, 3, 4)
        val expected = ByteString(content)
        val doc = PemDocument(PemLabel("LABEL"), content)
        // mutate the original byte array after construction
        content[0] = 9
        // content must be unaffected (constructor copies input)
        assertEquals(expected, doc.content)
    }

    @Test
    fun testEqualsHashCode() {
        val doc = PemDocument(PemLabel("LABEL"), byteArrayOf(1, 2, 3, 4))

        // equals/hashCode with the same logical content
        val doc2 = PemDocument(PemLabel("LABEL"), ByteString(1, 2, 3, 4))
        assertEquals(doc.content, doc2.content)
        assertEquals(doc, doc2)
        assertEquals(doc.hashCode(), doc2.hashCode())

        // different label -> not equal
        val doc3 = PemDocument(PemLabel("OTHER"), ByteString(1, 2, 3, 4))
        assertNotEquals(doc, doc3)

        // different content -> not equal
        val doc4 = PemDocument(PemLabel("LABEL"), ByteString(4, 3, 2, 1))
        assertNotEquals(doc, doc4)

    }

    @Test
    fun testToString() {
        assertEquals(
            "PemDocument(label=LABEL, content=ByteString(size=4 hex=01020304))",
            PemDocument(PemLabel("LABEL"), byteArrayOf(1, 2, 3, 4)).toString()
        )
    }

    @Test
    fun testDecodeToSequenceEmptyAndNoPem() {
        testPemDecodeSequence(emptyList(), "")
        testPemDecodeSequence(emptyList(), "no pem here")
    }

    @Test
    fun testDecodeToSequenceWithContentAroundAndBetween(): Unit = testPemDecodeSequence(
        expected = listOf(
            PemDocument(PemLabel.Certificate, "ONE".encodeToByteString()),
            PemDocument(PemLabel.Certificate, "TWO".encodeToByteString())
        ),
        document = """
        Some heading that should be ignored
        -----BEGIN CERTIFICATE-----
        T05F
        -----END CERTIFICATE-----
        Some text between documents should be ignored too
        -----BEGIN CERTIFICATE-----
        VFdP
        -----END CERTIFICATE-----
        Final trailing text that should be ignored as well
        """.trimIndent()
    )

    @Test
    fun testDecodeSourcePartialConsumption() {
        val pem = """
            IGNORE
            -----BEGIN X-----
            QQ==
            -----END X-----
            BETWEEN
            -----BEGIN X-----
            Qg==
            -----END X-----
            AFTER
        """.trimIndent()

        val buffer = Buffer()
        buffer.writeString(pem)

        assertEquals(
            expected = PemDocument(PemLabel("X"), "A".encodeToByteString()),
            // read from buffer one document
            actual = PemDocument.decode(buffer)
        )
        assertEquals(
            expected = PemDocument(PemLabel("X"), "B".encodeToByteString()),
            // read from buffer second document
            actual = PemDocument.decode(buffer)
        )

        assertEquals("AFTER", buffer.readString())
    }

    @Test
    fun testDecodeToSequenceSourcePartialConsumption() {
        val pem = """
            IGNORE
            -----BEGIN X-----
            QQ==
            -----END X-----
            BETWEEN
            -----BEGIN X-----
            Qg==
            -----END X-----
            AFTER
        """.trimIndent()

        val buffer = Buffer()
        buffer.writeString(pem)

        assertEquals(
            listOf(
                PemDocument(PemLabel("X"), "A".encodeToByteString()),
                PemDocument(PemLabel("X"), "B".encodeToByteString())
            ),
            PemDocument.decodeToSequence(buffer).take(2).toList()
        )

        assertEquals("AFTER", buffer.readString())
    }

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
    fun testDecodingWithEmpty() = testPemDecodeFailure(
        document = ""
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

    @Test
    fun testDecodingWithMissingNewLineAfterBegin() = testPemDecodeFailure(
        document = "-----BEGIN X-----"
    ) {
        assertIs<IllegalArgumentException>(it)
        assertEquals("Invalid PEM format: missing new line after BEGIN label", it.message)
    }

    @Test
    fun testDecodingWithMissingBeginLabelSuffix() = testPemDecodeFailure(
        document = "-----BEGIN X\nQQ==\n-----END X-----"
    ) {
        assertIs<IllegalArgumentException>(it)
        assertEquals("Invalid PEM format: missing BEGIN label suffix", it.message)
    }

    @Test
    fun testDecodingWithMissingEndLabelSuffix() = testPemDecodeFailure(
        document = "-----BEGIN X-----\nQQ==\n-----END X"
    ) {
        assertIs<IllegalArgumentException>(it)
        assertEquals("Invalid PEM format: missing END label suffix", it.message)
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

    private fun testPemDecodeSequence(
        expected: List<PemDocument>,
        document: String,
    ) {
        fun assertSequenceEquals(expectedDocs: List<PemDocument>, actualSeq: Sequence<PemDocument>) {
            assertEquals(expectedDocs, actualSeq.toList())
        }

        assertSequenceEquals(expected, PemDocument.decodeToSequence(document))
        assertSequenceEquals(expected, PemDocument.decodeToSequence(document.encodeToByteArray()))
        assertSequenceEquals(expected, PemDocument.decodeToSequence(document.encodeToByteString()))
        assertSequenceEquals(expected, PemDocument.decodeToSequence(Buffer().also {
            it.write(document.encodeToByteArray())
        }))
        assertSequenceEquals(expected, PemDocument.decodeToSequence((Buffer().also {
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
