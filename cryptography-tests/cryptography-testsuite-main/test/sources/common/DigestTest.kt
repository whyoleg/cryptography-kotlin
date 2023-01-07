package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.random.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class DigestTest {
    @OptIn(InsecureAlgorithm::class, ExperimentalCoroutinesApi::class)
    @Test
    fun test() = runTest {
        supportedProviders.forEach { provider ->
            val hasher = provider.get(SHA512).hasher()

            repeat(100) {
                val dataSize = CryptographyRandom.nextInt(10000)
                val data = CryptographyRandom.nextBytes(dataSize)
                val h1 = hasher.hash(data)
                val h2 = hasher.hash(data)
                h2.assertContentEquals(h1)
            }
        }
    }
}
