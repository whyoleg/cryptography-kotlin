package dev.whyoleg.cryptography.providers.jdk

import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class PoolingTest {

    @Test
    fun testSequentialAccessOnCachedPoolShouldReuseInstance() {
        var instantiateCount = 0
        val pool = Pooled.Cached { instantiateCount++; Any() }
        repeat(3) {
            pool.use { }
        }
        assertEquals(1, instantiateCount)
    }

    @Test
    fun testConcurrentAccessOnCachedPoolShouldNotReuseInstances() = runTest {
        var instantiateCount = 0
        val pool = Pooled.Cached { instantiateCount++; Any() }
        pool.use { } // prime the pool with 1 instance; we should not be able to reuse that instance for all 3 concurrent usages below
        List(3) {
            launch {
                pool.use {
                    delay(1000)
                }
            }
        }.joinAll()
        assertEquals(3, instantiateCount)
    }
}
