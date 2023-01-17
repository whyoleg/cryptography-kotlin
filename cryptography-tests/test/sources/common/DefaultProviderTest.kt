package dev.whyoleg.cryptography.tests

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.support.*
import kotlin.test.*

class DefaultProviderTest {
    @Test
    fun test() {
        val defaultName = CryptographyProvider.Default.name
        assertContains(availableProviders.map { it.name }, defaultName)
    }
}
