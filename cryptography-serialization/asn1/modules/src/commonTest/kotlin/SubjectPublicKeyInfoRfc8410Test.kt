/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.decodeFromByteArray
import kotlin.test.*

class SubjectPublicKeyInfoRfc8410Test {
    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0)
        return ByteArray(length / 2) { i ->
            val hi = this[i * 2].digitToInt(16)
            val lo = this[i * 2 + 1].digitToInt(16)
            ((hi shl 4) or lo).toByte()
        }
    }

    @Test
    fun spki_Ed25519_absentParameters() {
        val bytes = "300a300506032b6570030100".hexToBytes()
        val spki = Der.decodeFromByteArray<SubjectPublicKeyInfo>(bytes)
        assertEquals(ObjectIdentifier.Ed25519, spki.algorithm.algorithm)
    }

    @Test
    fun spki_Ed25519_nullParameters() {
        val bytes = "300c300706032b65700500030100".hexToBytes()
        val spki = Der.decodeFromByteArray<SubjectPublicKeyInfo>(bytes)
        assertEquals(ObjectIdentifier.Ed25519, spki.algorithm.algorithm)
    }
}

