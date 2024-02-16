/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.internal.*
import kotlinx.serialization.*
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class ObjectIdentifierEncoding {

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

    private fun checkOid(
        oid: String,
        hex: String,
    ) {
        val value = ObjectIdentifier(oid)
        val bytes = ByteArrayOutput().also { DerOutput(it).writeObjectIdentifier(value) }.toByteArray()

        assertEquals(hex, bytes.toHexString())
        assertEquals(value, DerInput(ByteArrayInput(bytes)).readObjectIdentifier())

        assertContentEquals(bytes, DER.encodeToByteArray(value))
        assertEquals(value, DER.decodeFromByteArray(bytes))
    }
}
