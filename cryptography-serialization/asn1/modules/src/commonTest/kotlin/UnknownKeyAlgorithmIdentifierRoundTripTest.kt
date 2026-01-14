/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.test.*

class UnknownKeyAlgorithmIdentifierRoundTripTest {

    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0)
        return ByteArray(length / 2) { i ->
            val hi = this[i * 2].digitToInt(16)
            val lo = this[i * 2 + 1].digitToInt(16)
            ((hi shl 4) or lo).toByte()
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    @Test
    fun roundTrip_unknownOid_withNonNullParams_preservesRawTlv() {
        // AlgorithmIdentifier ::= SEQUENCE {
        //   algorithm  OBJECT IDENTIFIER 1.2.3.4 (06 03 2A 03 04)
        //   parameters OCTET STRING 0xDE 0xAD (04 02 DE AD)
        // }
        val ai = "300906032a03040402dead".hexToBytes()

        val decoded = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(ai)
        assertTrue(decoded is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier("1.2.3.4"), decoded.algorithm)

        val params = decoded.parameters
        assertNotNull(params)
        assertTrue(params is Asn1Any)
        assertEquals("0402dead", params.bytes.toHex())

        // Re-encode should be byte-for-byte identical
        val re = Der.encodeToByteArray(KeyAlgorithmIdentifier.serializer(), decoded)
        assertEquals(ai.toHex(), re.toHex())
    }
}
