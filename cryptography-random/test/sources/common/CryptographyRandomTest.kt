package dev.whyoleg.cryptography.random

import kotlin.math.*
import kotlin.test.*

class CryptographyRandomTest {
    @Test
    fun testInt() {
        assertNotEquals(CryptographyRandom.nextInt(), CryptographyRandom.nextInt())
    }

    @Test
    fun test65536() {
        //WebCrypto specific test - improve it somehow?
        assertTrue(CryptographyRandom.nextBytes(65535).any { it != 0.toByte() })
        assertTrue(CryptographyRandom.nextBytes(65536).any { it != 0.toByte() })
        assertTrue(CryptographyRandom.nextBytes(65537).any { it != 0.toByte() })
    }

    @Test
    fun testArray() {
        repeat(8) { n ->
            val size = 10.0.pow(n).toInt()
            val array = CryptographyRandom.nextBytes(size)
            assertTrue(array.any { it != 0.toByte() })
            assertEquals(size, array.size)
        }
    }

    @Test
    fun testEmpty() {
        assertTrue(CryptographyRandom.nextBytes(0).isEmpty())
        assertTrue(CryptographyRandom.nextBytes(ByteArray(0)).isEmpty())
    }

    @Test
    fun testInPlace() {
        val bytes = ByteArray(10) { it.toByte() }
        bytes.copyOf().also { copy ->
            assertContentEquals(bytes, copy)
            assertFalse(bytes.contentEquals(CryptographyRandom.nextBytes(copy)))
            assertFalse(bytes.contentEquals(copy))
        }
        bytes.copyOf().also { copy ->
            assertContentEquals(bytes, CryptographyRandom.nextBytes(copy, 5, 5))
            assertContentEquals(bytes, copy)
        }
        bytes.copyOf().also { copy ->
            assertFalse(bytes.contentEquals(CryptographyRandom.nextBytes(copy, 0, 5)))
            assertFalse(bytes.contentEquals(copy))
        }
    }

}
