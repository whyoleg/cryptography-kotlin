/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

abstract class XdhTest(provider: CryptographyProvider) : AlgorithmTest<XDH>(XDH, provider) {

    @Test
    fun testDeriveSharedSecret() = testWithAlgorithm {
        val curves = listOf(XDH.Curve.X25519, XDH.Curve.X448).filter { curve ->
            // CryptoKit supports only X25519
            !(context.provider.isCryptoKit && curve == XDH.Curve.X448)
        }.ifEmpty { listOf(XDH.Curve.X25519) }
        var anyRan = false
        curves.forEach { curve ->
            val a = try {
                algorithm.keyPairGenerator(curve).generateKey()
            } catch (t: Throwable) {
                if (context.provider.isWebCrypto) {
                    logger.print("SKIP: '${curve.name}' is not supported")
                    return@forEach
                } else throw t
            }
            val b = algorithm.keyPairGenerator(curve).generateKey()
            anyRan = true

            val aSecret = a.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(b.publicKey)
            val bSecret = b.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(a.publicKey)
            assertContentEquals(aSecret, bSecret)
            val expectedSize = when (curve) {
                XDH.Curve.X25519 -> 32
                XDH.Curve.X448   -> 56
            }
            assertEquals(expectedSize, aSecret.size)
        }
        if (!anyRan && context.provider.isWebCrypto) return@testWithAlgorithm
    }
}
