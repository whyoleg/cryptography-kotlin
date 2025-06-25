/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class PoolingTest {

    @Test
    fun testSequentialUseCachedPool() {
        val pool = Pooled.Cached(::Any)
        val first = pool.use { it }
        val second = pool.use { it }
        assertSame(first, second)
        val third = pool.use { it }
        assertSame(second, third)
    }

    @Test
    fun testOverlappingUseCachedPool() {
        val pool = Pooled.Cached(::Any)
        val first = pool.use { it }
        pool.use { i1 ->
            assertSame(first, i1)
            pool.use { i2 ->
                assertNotSame(i1, i2)
                pool.use { i3 ->
                    assertNotSame(i2, i3)
                }
            }
        }
    }

    @Test
    fun testConcurrentUseCachedPool() = runTest {
        val pool = Pooled.Cached(::Any)
        val first = pool.use { it }
        val instances = List(3) {
            async {
                pool.use { instance ->
                    delay(1000)
                    instance
                }
            }
        }.awaitAll()
        assertSame(first, instances[0])
        assertNotSame(instances[0], instances[1])
        assertNotSame(instances[1], instances[2])
    }
}
