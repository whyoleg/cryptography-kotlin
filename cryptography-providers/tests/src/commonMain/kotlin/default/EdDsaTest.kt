/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

abstract class EdDsaTest(provider: CryptographyProvider) : AlgorithmTest<EdDSA>(EdDSA, provider), SignatureTest {

    @Test
    fun testSignVerify() = testWithAlgorithm {
        listOf(EdDSA.Curve.Ed25519, EdDSA.Curve.Ed448).forEach { curve ->
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            val dataSets = listOf(
                ByteArray(0),
                CryptographyRandom.nextBytes(32),
                CryptographyRandom.nextBytes(1024)
            )
            val signer = keyPair.privateKey.signatureGenerator()
            val verifier = keyPair.publicKey.signatureVerifier()
            dataSets.forEach { data ->
                val signature = signer.generateSignature(data)
                assertTrue(verifier.tryVerifySignature(data, signature))
            }
        }
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) return@testWithAlgorithm

        listOf(EdDSA.Curve.Ed25519, EdDSA.Curve.Ed448).forEach { curve ->
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()
            repeat(5) {
                val size = CryptographyRandom.nextInt(256, 4096)
                val data = ByteString(CryptographyRandom.nextBytes(size))
                assertSignaturesViaFunction(keyPair.privateKey.signatureGenerator(), keyPair.publicKey.signatureVerifier(), data)
            }
        }
    }
}

