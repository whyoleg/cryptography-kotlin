/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

import kotlinx.coroutines.test.*
import kotlin.test.*
import kotlin.uuid.*

class TestStorageClientTest {
    @Test
    fun testRoundtrip() = runTest {
        val storage = TestStorageClient.logging(TestStorageClient.default())
        val id = Uuid.random().toString()
        val data = "Hello, hello"
        storage.save(arrayOf("testhost", id), data)
        assertEquals(data, storage.get(arrayOf("testhost", id)))
        assertContains(storage.list(arrayOf("testhost")), id)
    }
}
