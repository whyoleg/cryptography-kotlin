/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

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
            Pem.encode(
                PemContent(
                    PemLabel("UNKNOWN"),
                    "Hello World".encodeToByteArray()
                )
            )
        )
    }

    @Test
    fun testDecoding() {
        val content = Pem.decode(
            """
            -----BEGIN UNKNOWN-----
            SGVsbG8gV29ybGQ=
            -----END UNKNOWN-----
            
            """.trimIndent(),
        )

        assertEquals(PemLabel("UNKNOWN"), content.label)
        assertEquals("Hello World", content.bytes.decodeToString())
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
            Pem.encode(
                PemContent(
                    PemLabel("UNKNOWN CHUNKED"),
                    "Hello World".repeat(10).encodeToByteArray()
                )
            )
        )
    }

    @Test
    fun testChunkedDecoding() {
        val content = Pem.decode(
            """
            -----BEGIN UNKNOWN CHUNKED-----
            SGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxs
            byBXb3JsZEhlbGxvIFdvcmxkSGVsbG8gV29ybGRIZWxsbyBXb3JsZEhlbGxvIFdv
            cmxkSGVsbG8gV29ybGQ=
            -----END UNKNOWN CHUNKED-----
            
            """.trimIndent(),
        )

        assertEquals(PemLabel("UNKNOWN CHUNKED"), content.label)
        assertEquals("Hello World".repeat(10), content.bytes.decodeToString())
    }

    @Test
    fun testDecodingWithComment() {
        val content = Pem.decode(
            """
            Here is some description for pem
            it should not affect anything
            -----BEGIN UNKNOWN-----
            SGVsbG8gV29ybGQ=
            -----END UNKNOWN-----
            """.trimIndent(),
        )

        assertEquals(PemLabel("UNKNOWN"), content.label)
        assertEquals("Hello World", content.bytes.decodeToString())
    }

    @Test
    fun testDecodingWithNoBeginLabel() {
        assertFails {
            Pem.decode("SGVsbG8gV29ybGQ=\n-----END UNKNOWN-----")
        }
    }

    @Test
    fun testDecodingWithNoEndLabel() {
        assertFails {
            Pem.decode("-----BEGIN UNKNOWN-----\nSGVsbG8gV29ybGQ=")
        }
    }

    @Test
    fun testDecodingWithDifferentLabels() {
        assertFails {
            Pem.decode(
                """
                -----BEGIN UNKNOWN1-----
                SGVsbG8gV29ybGQ=
                -----END UNKNOWN2-----
                """.trimIndent(),
            )
        }
    }

}
