/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.internal.*
import kotlinx.serialization.*
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class ObjectIdentifierEncodingTest {

    @Test
    fun testSha256WithRSAEncryption() = checkOid(
        oid = "1.2.840.113549.1.1.11",
        hex = "06092a864886f70d01010b"
    )

    @Test
    fun testRSAEncryption() = checkOid(
        oid = "1.2.840.113549.1.1.1",
        hex = "06092a864886f70d010101"
    )

    @Test
    fun testOidWithZeroElement() = checkOid(
        oid = "1.3.132.0.34",
        hex = "06052b81040022"
    )

    @Test
    fun testOidWithRedundantZero() = checkOid(
        oid = "1.2.840.10045.2.1",
        hex = "06072a8648ce3d0201"
    )

    private fun checkOid(
        oid: String,
        hex: String,
    ) {
        val value = ObjectIdentifier(oid)
        val bytes = ByteArrayOutput().also { DerOutput(it).writeObjectIdentifier(null, value) }.toByteArray()

        assertEquals(hex, bytes.toHexString())
        assertEquals(value, DerInput(ByteArrayInput(bytes)).readObjectIdentifier(null))

        assertContentEquals(bytes, DER.encodeToByteArray(value))
        assertEquals(value, DER.decodeFromByteArray(bytes))
    }
}
