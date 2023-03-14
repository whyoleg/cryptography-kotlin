/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class EcdsaTest {

    //all sizes are in bytes
    data class EcdsaSize(
        val curve: EC.Curve,
        val rawSignatureSize: Int,
        val derSignatureSizes: List<Int>,
        val publicKeySize: Int,
        val privateKeySizes: List<Int>, //list is because of different formats (PKCS#8 and SEC1)
    )

    @Test
    fun testSizes() = runTestForEachAlgorithm(ECDSA) {
        listOf(
            EcdsaSize(EC.Curve.P256, 64, listOf(69, 70, 71, 72), 91, listOf(67, 138)),
            EcdsaSize(EC.Curve.P384, 96, listOf(101, 102, 103, 104), 120, listOf(80, 185)),
            EcdsaSize(EC.Curve.P521, 132, listOf(136, 137, 138, 139), 158, listOf(98, 241)),
        ).forEach { (curve, rawSignatureSize, derSignatureSizes, publicKeySize, privateKeySizes) ->
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            assertEquals(publicKeySize, keyPair.publicKey.encodeTo(EC.PublicKey.Format.DER).size)
            assertContains(privateKeySizes, keyPair.privateKey.encodeTo(EC.PrivateKey.Format.DER).size)

            generateDigests { digest, _ ->
                if (supportsSignatureFormat(ECDSA.SignatureFormat.RAW)) {
                    keyPair.privateKey.signatureGenerator(digest, ECDSA.SignatureFormat.RAW).run {
                        assertEquals(rawSignatureSize, generateSignature(ByteArray(0)).size)
                        repeat(8) { n ->
                            val size = 10.0.pow(n).toInt()
                            val data = CryptographyRandom.nextBytes(size)
                            assertEquals(rawSignatureSize, generateSignature(data).size)
                        }
                    }
                }
                if (supportsSignatureFormat(ECDSA.SignatureFormat.DER)) {
                    keyPair.privateKey.signatureGenerator(digest, ECDSA.SignatureFormat.DER).run {
                        assertContains(derSignatureSizes, generateSignature(ByteArray(0)).size)
                        repeat(8) { n ->
                            val size = 10.0.pow(n).toInt()
                            val data = CryptographyRandom.nextBytes(size)
                            assertContains(derSignatureSizes, generateSignature(data).size)
                        }
                    }
                }
            }
        }
    }
}
