package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.test.*

class DefaultProviderTest {
    @Test
    fun test() {
        val defaultName = kotlin.runCatching { CryptographyProvider.Default.name }
        if (availableProviders.isEmpty()) return
        assertContains(availableProviders.map { it.name }, defaultName.getOrThrow())
    }
}
