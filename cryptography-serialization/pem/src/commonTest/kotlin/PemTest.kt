/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.bytestring.*
import kotlin.test.*

class PemTest {

    @Test
    fun testEncoding() {
        assertEquals(
            """
            -----BEGIN UNKNOWN-----
            SGVsbG8gV29ybGQ=
            -----END UNKNOWN-----
            
            """.trimIndent(),
            PemDocument(
                PemLabel("UNKNOWN"),
                "Hello World".encodeToByteArray()
            ).encodeToString()
        )
    }

    @Test
    fun testDecoding() {
        val content = PemDocument.decode(
            """
            -----BEGIN UNKNOWN-----
            SGVsbG8gV29ybGQ=
            -----END UNKNOWN-----
            
            """.trimIndent(),
        )

        assertEquals(PemLabel("UNKNOWN"), content.label)
        assertEquals("Hello World", content.content.decodeToString())
    }

    @Test
    fun testChunkedEncoding() {
        assertEquals(
            """
            -----BEGIN UNKNOWN CHUNKED-----
            SGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxs
            byBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdv
            cmxkSGVsbG8gV29ybGQ=
            -----END UNKNOWN CHUNKED-----
            
            """.trimIndent(),
            PemDocument(
                PemLabel("UNKNOWN CHUNKED"),
                "Hello World".repeat(10).encodeToByteArray()
            ).encodeToString().lines().joinToString("\n")
        )
    }

    @Test
    fun testChunkedDecoding() {
        val content = PemDocument.decode(
            """
            -----BEGIN UNKNOWN CHUNKED-----
            SGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxs
            byBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdv
            cmxkSGVsbG8gV29ybGQ=
            -----END UNKNOWN CHUNKED-----
            
            """.trimIndent(),
        )

        assertEquals(PemLabel("UNKNOWN CHUNKED"), content.label)
        assertEquals("Hello World".repeat(10), content.content.decodeToString())
    }

    @Test
    fun testDecodingWithComment() {
        val content = PemDocument.decode(
            """
            Here is some description for pem
            it should not affect anything
            -----BEGIN UNKNOWN-----
            SGVsbG8gV29ybGQ=
            -----END UNKNOWN-----
            """.trimIndent(),
        )

        assertEquals(PemLabel("UNKNOWN"), content.label)
        assertEquals("Hello World", content.content.decodeToString())
    }

    @Test
    fun testDecodingWithNoBeginLabel() {
        assertFails {
            PemDocument.decode("SGVsbG8gV29ybGQ=\n-----END UNKNOWN-----")
        }
    }

    @Test
    fun testDecodingWithNoEndLabel() {
        assertFails {
            PemDocument.decode("-----BEGIN UNKNOWN-----\nSGVsbG8gV29ybGQ=")
        }
    }

    @Test
    fun testDecodingWithDifferentLabels() {
        assertFails {
            PemDocument.decode(
                """
                -----BEGIN UNKNOWN1-----
                SGVsbG8gV29ybGQ=
                -----END UNKNOWN2-----
                """.trimIndent(),
            )
        }
    }

}
