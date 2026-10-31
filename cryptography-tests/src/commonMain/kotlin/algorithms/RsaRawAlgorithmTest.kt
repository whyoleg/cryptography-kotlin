/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.io.bytestring.*

// RSA-RAW -> [key size] -> [key pair] -> [data]
abstract class RsaRawAlgorithmTest(cryptographyProvider: CryptographyProvider) :
    RsaAlgorithmTest<RSA.RAW, RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair, CipherTestDataValidator>(
        provider = cryptographyProvider,
        algorithmId = RSA.RAW,
        algorithmLimitation = {
            when {
                provider.isWebCrypto || provider.isCryptoKit -> fails("RSA-RAW is not supported")
                else                                         -> null
            }
        },
        singleDigest = true,
    ) {
    override fun TestValidatorScope.keyValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.RAW.PublicKey>,
        privateKeys: List<RSA.RAW.PrivateKey>,
    ): CipherTestDataValidator = ciphertexts(
        encryptors = publicKeys.map { it.encryptor() },
        decryptors = privateKeys.map { it.decryptor() },
        ivSize = 0,
        ciphertextSize = { parameters.keySize },
        deterministic = true,
    )

    context(context: TestGenerationContext)
    override suspend fun CipherTestDataValidator.generateRandom(parameters: RsaTestParameters, keyPair: RSA.RAW.KeyPair) {
        // plaintext has the size of the key, leading zero byte makes it smaller than the modulus
        val plaintexts = List(3) { ByteString(byteArrayOf(0) + CryptographyRandom.nextBytes(parameters.keySize - 1)) }
        generateCiphertextsFor(keyPair.publicKey.encryptor(), plaintexts)
    }
}
