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
        val curves = listOf(EdDSA.Curve.Ed25519, EdDSA.Curve.Ed448).filter { curve ->
            // CryptoKit supports only Ed25519
            !(context.provider.isCryptoKit && curve == EdDSA.Curve.Ed448)
        }.ifEmpty { listOf(EdDSA.Curve.Ed25519) }
        var anyRan = false
        curves.forEach { curve ->
            val keyPair = try {
                algorithm.keyPairGenerator(curve).generateKey()
            } catch (t: Throwable) {
                if (context.provider.isWebCrypto) {
                    logger.print("SKIP: '${curve.name}' is not supported")
                    return@forEach
                } else throw t
            }
            anyRan = true

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
        if (!anyRan && context.provider.isWebCrypto) return@testWithAlgorithm
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) return@testWithAlgorithm

        val curves = listOf(EdDSA.Curve.Ed25519, EdDSA.Curve.Ed448).filter { curve ->
            !(context.provider.isCryptoKit && curve == EdDSA.Curve.Ed448)
        }.ifEmpty { listOf(EdDSA.Curve.Ed25519) }
        curves.forEach { curve ->
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()
            repeat(5) {
                val size = CryptographyRandom.nextInt(256, 4096)
                val data = ByteString(CryptographyRandom.nextBytes(size))
                assertSignaturesViaFunction(keyPair.privateKey.signatureGenerator(), keyPair.publicKey.signatureVerifier(), data)
            }
        }
    }
}
