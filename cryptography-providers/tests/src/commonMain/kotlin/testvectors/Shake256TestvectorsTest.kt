/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

// FIPS 202 SHAKE256 examples (empty input and the ASCII string "abc").
abstract class Shake256TestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<XOF>(SHAKE256, provider) {
    @Test
    fun fips202EmptyInput() = testWithAlgorithm {
        assertEquals(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762" +
                    "fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            algorithm.hasher(64.bytes).hash(ByteArray(0)).toHexString(),
        )
    }

    @Test
    fun fips202Abc() = testWithAlgorithm {
        assertEquals(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
                    "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
            algorithm.hasher(64.bytes).hash("abc".encodeToByteArray()).toHexString(),
        )
    }
}
