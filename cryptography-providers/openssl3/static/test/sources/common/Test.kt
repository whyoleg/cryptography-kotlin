package dev.whyoleg.cryptography.openssl3.static

import dev.whyoleg.cryptography.openssl3.*
import kotlin.test.*

class SomeTest {

    @Test
    fun test() {
        assertTrue(init().startsWith("3."))
    }
}
