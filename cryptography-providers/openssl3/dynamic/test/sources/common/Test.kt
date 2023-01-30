package dev.whyoleg.cryptography.openssl3.dynamic

import dev.whyoleg.cryptography.openssl3.*
import kotlin.test.*

class SomeTest {

    @Test
    fun test() {
        val version = init()
        assertTrue(version!!.startsWith("3."), "Version: $version")

        assertEquals(3, major())
    }
}
