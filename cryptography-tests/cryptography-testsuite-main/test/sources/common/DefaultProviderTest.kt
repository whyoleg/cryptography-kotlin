package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.provider.*
import kotlin.test.*

class DefaultProviderTest {
    @Test
    fun test() {
        println(CryptographyProvider.Default.name)
    }
}
