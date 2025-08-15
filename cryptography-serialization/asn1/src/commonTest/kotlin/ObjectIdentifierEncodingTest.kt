/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlin.test.*

// TODO: test with UUID
class ObjectIdentifierEncodingTest {

    @Test
    fun testSha256WithRSAEncryption() = checkOid(
        oid = "1.2.840.113549.1.1.11",
        hex = "2a864886f70d01010b"
    )

    @Test
    fun testRSAEncryption() = checkOid(
        oid = "1.2.840.113549.1.1.1",
        hex = "2a864886f70d010101"
    )

    @Test
    fun testOidWithZeroElement() = checkOid(
        oid = "1.3.132.0.34",
        hex = "2b81040022"
    )

    @Test
    fun testOidWithRedundantZero() = checkOid(
        oid = "1.2.840.10045.2.1",
        hex = "2a8648ce3d0201"
    )

    private fun checkOid(oid: String, hex: String) {
        val oidFromString = ObjectIdentifier.parse(oid)
        val oidFromBytes = ObjectIdentifier.fromDerBytes(hex.hexToByteArray())

        assertEquals(oid, oidFromString.toString())
        assertEquals(oid, oidFromBytes.toString())

        assertEquals(hex, oidFromString.toDerBytes().toHexString())
        assertEquals(hex, oidFromBytes.toDerBytes().toHexString())

        assertEquals(oidFromString, oidFromBytes)
        assertEquals(oidFromString.hashCode(), oidFromBytes.hashCode())
    }
}
