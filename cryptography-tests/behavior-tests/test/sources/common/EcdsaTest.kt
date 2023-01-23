package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class EcdsaTest {

    @Test
    fun testSizes() = runTestForEachAlgorithm(ECDSA) {
        listOf(
            //validate DER values
            Triple(EC.Curve.P256, 64.bytes, listOf(70, 71, 72)),
            Triple(EC.Curve.P384, 96.bytes, listOf(101, 102, 103, 104)),
            Triple(EC.Curve.P521, 132.bytes, listOf(137, 138, 139)),
        ).forEach { (curve, rawSignatureSize, derSignatureSizes) ->
            generateDigests { digest, _ ->
                val key = algorithm.keyPairGenerator(curve).generateKey().privateKey
                if (supportsSignatureFormat(ECDSA.SignatureFormat.RAW)) key.signatureGenerator(digest, ECDSA.SignatureFormat.RAW).run {
                    assertEquals(rawSignatureSize.inBytes, generateSignature(ByteArray(0)).size)
                    repeat(8) { n ->
                        val size = 10.0.pow(n).toInt()
                        val data = CryptographyRandom.nextBytes(size)
                        assertEquals(rawSignatureSize.inBytes, generateSignature(data).size)
                    }
                }
                if (supportsSignatureFormat(ECDSA.SignatureFormat.DER)) key.signatureGenerator(digest, ECDSA.SignatureFormat.DER).run {
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
