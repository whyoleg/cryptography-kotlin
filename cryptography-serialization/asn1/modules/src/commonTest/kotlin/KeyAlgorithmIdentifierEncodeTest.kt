/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlin.test.*

class KeyAlgorithmIdentifierEncodeTest {

    private fun ByteArray.toHex() = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0)
        return ByteArray(length / 2) { i ->
            val hi = this[i * 2].digitToInt(16)
            val lo = this[i * 2 + 1].digitToInt(16)
            ((hi shl 4) or lo).toByte()
        }
    }

    @Test
    fun encode_Ed25519_absentParameters() {
        val id: KeyAlgorithmIdentifier = UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519)
        val bytes = Der.encodeToByteArray(id)
        assertEquals("300506032b6570", bytes.toHex())
    }

    @Test
    fun encode_X25519_absentParameters() {
        val id: KeyAlgorithmIdentifier = UnknownKeyAlgorithmIdentifier(ObjectIdentifier.X25519)
        val bytes = Der.encodeToByteArray(id)
        assertEquals("300506032b656e", bytes.toHex())
    }

    @Test
    fun encode_RSA_nullParameters() {
        val id: KeyAlgorithmIdentifier = RsaKeyAlgorithmIdentifier
        val bytes = Der.encodeToByteArray(id)
        assertEquals("300d06092a864886f70d0101010500", bytes.toHex())
    }

    @Test
    fun roundTrip_Ed25519_null_normalizedToAbsent() {
        val withNull = "300706032b65700500".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(withNull)
        val reencoded = Der.encodeToByteArray(id)
        assertEquals("300506032b6570", reencoded.toHex())
    }
}

