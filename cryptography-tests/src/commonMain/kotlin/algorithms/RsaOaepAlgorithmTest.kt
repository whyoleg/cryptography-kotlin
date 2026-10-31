/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*

// RSA-OAEP -> [digest, key size] -> [key pair] -> [data] with label as associated data
abstract class RsaOaepAlgorithmTest(cryptographyProvider: CryptographyProvider) :
    RsaAlgorithmTest<RSA.OAEP, RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair, CipherTestDataValidator>(
        provider = cryptographyProvider,
        algorithmId = RSA.OAEP,
        algorithmLimitation = {
            when {
                provider.isCryptoKit -> fails("RSA-OAEP is not supported")
                else                 -> null
            }
        },
    ) {
    override fun TestValidatorScope.keyValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.OAEP.PublicKey>,
        privateKeys: List<RSA.OAEP.PrivateKey>,
    ): CipherTestDataValidator = ciphertexts(
        encryptors = publicKeys.map { it.encryptor() },
        decryptors = privateKeys.map { it.decryptor() },
        ivSize = 0,
        ciphertextSize = { parameters.keySize },
        deterministic = false,
        limitation = { operation ->
            when (operation) {
                is CipherTestOperation.Encrypt if operation.associatedDataSize != null && provider.isApple
                     -> fails("Associated data (label) is not supported")
                is CipherTestOperation.Decrypt if operation.associatedDataSize != null && provider.isApple
                     -> fails("Associated data (label) is not supported")
                is CipherTestOperation.Encrypt,
                     -> failsOnEmptyInput(operation.plaintextSize)
                else -> null
            }
        },
    )

    context(context: TestGenerationContext)
    override suspend fun CipherTestDataValidator.generateRandom(parameters: RsaTestParameters, keyPair: RSA.OAEP.KeyPair) {
        val encryptor = keyPair.publicKey.encryptor()
        val maxPlaintextSize = parameters.keySize - 2 - 2 * parameters.digest.digestSize
        val plaintextSizes = listOf(0, 1, maxPlaintextSize / 2, maxPlaintextSize)
        generateCiphertexts(encryptor, plaintextSizes)
        // empty label is the same as no label
        generateCiphertexts(encryptor, listOf(0, maxPlaintextSize), associatedDataSize = 0)
        generateCiphertexts(encryptor, plaintextSizes, associatedDataSize = 100)
        // random bytes are not a valid OAEP ciphertext
        invalidCiphertexts(parameters.keySize)
    }
}
