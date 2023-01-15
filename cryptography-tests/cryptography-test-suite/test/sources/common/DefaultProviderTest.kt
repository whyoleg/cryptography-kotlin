package dev.whyoleg.cryptography.test.suite

import dev.whyoleg.cryptography.provider.*
import kotlin.test.*

//TODO: move it somewhere else?
class DefaultProviderTest {
    @Test
    fun test() {
        val defaultName = CryptographyProvider.Default.name
        println(defaultName)
        assertContains(supportedProviders.map { it.name }, defaultName)
    }
}
