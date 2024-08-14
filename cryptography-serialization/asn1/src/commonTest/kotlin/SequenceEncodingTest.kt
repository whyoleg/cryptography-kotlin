/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class SequenceEncodingTest {

    @Serializable
    class SimpleAlgorithmIdentifier(
        val algorithm: ObjectIdentifier,
        val parameters: Nothing?,
    )

    @Test
    fun testAlgorithmIdentifier() {
        val algorithm = SimpleAlgorithmIdentifier(ObjectIdentifier("1.2.840.113549.1.1.11"), null)
        val bytes = Der.encodeToByteArray(algorithm)
        assertEquals("300d06092a864886f70d01010b0500", bytes.toHexString())

        val decoded = Der.decodeFromByteArray<SimpleAlgorithmIdentifier>(bytes)

        assertEquals(algorithm.algorithm, decoded.algorithm)
        assertNull(decoded.parameters)
    }
}
