/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlin.test.*

typealias EcdhTestGroupValidator =
        EcTestGroupValidator<EcKeyAgreementTestGroupValidator<ECDH.PublicKey, ECDH.PrivateKey, SharedSecretTestDataValidator>>

// ECDH -> [curve] -> [two key pairs] -> [shared secret]
abstract class EcdhAlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<ECDH, EcdhTestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = ECDH,
    algorithmLimitation = {
        when {
            provider.isApple -> fails("ECDH is not supported")
            else             -> null
        }
    },
) {
    override fun TestValidatorScope.validator(algorithm: ECDH): EcdhTestGroupValidator = ecCurves(algorithm) { curve, keys ->
        keyAgreements(keys) { first, second ->
            sharedSecrets(
                first = first,
                second = second,
                publicKeyGenerator = { it.sharedSecretGenerator() },
                privateKeyGenerator = { it.sharedSecretGenerator() },
                sharedSecretSize = curve.orderSize,
            )
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        ecTestCurves.forEach { curve ->
            group(EcTestParameters(curve)) {
                generateKeyAgreementGroups(
                    generator = algorithm.keyPairGenerator(curve),
                    iterations = 3,
                    publicKey = ECDH.KeyPair::publicKey,
                    privateKey = ECDH.KeyPair::privateKey,
                ) { first, second ->
                    generateSharedSecret(first.privateKey.sharedSecretGenerator(), second.publicKey)
                }
            }
        }
    }
}
