package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*

private const val associatedDataIterations = 5
private const val cipherIterations = 5
private const val maxAssociatedDataSize = 10000

class RsaOaepTest : RsaBasedTest<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair, RSA.OAEP>(RSA.OAEP) {
    override suspend fun generate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: RSA.OAEP) {
        val cipherParametersId = api.ciphers.saveParameters(TestVectorParameters.Empty)
        generateKeys(logging, api, provider, algorithm) { keyPair, keyReference, keyParameters ->
            val maxPlaintextSize = keyParameters.keySize.inBytes - 2 - 2 * keyParameters.digestSize
            logging.log("maxPlaintextSize.size = $maxPlaintextSize")
            val encryptor = keyPair.publicKey.encryptor()
            val decryptor = keyPair.privateKey.decryptor()
            repeat(associatedDataIterations) { adIndex ->
                val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                logging.log("associatedData.size   = $associatedDataSize")
                val associatedData = associatedDataSize?.let(CryptographyRandom::nextBytes)
                repeat(cipherIterations) {
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                    logging.log("plaintext.size        = $plaintextSize")
                    val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                    val ciphertext = encryptor.encrypt(plaintext, associatedData)
                    logging.log("ciphertext.size       = ${ciphertext.size}")

                    decryptor.decrypt(ciphertext, associatedData).assertContentEquals(plaintext)

                    api.ciphers.saveData(cipherParametersId, AuthenticatedCipherData(keyReference, associatedData, plaintext, ciphertext))
                }
            }
        }
    }

    override suspend fun validate(
        logging: TestLoggingContext,
        api: TestVectorApi,
        provider: CryptographyProvider,
        algorithm: RSA.OAEP,
    ) {
        val keyPairs = validateKeys(logging, api, provider, algorithm)

        api.ciphers.getParameters<TestVectorParameters.Empty> { _, parametersId ->
            api.ciphers.getData<AuthenticatedCipherData>(parametersId) { (keyReference, associatedData, plaintext, ciphertext), _ ->
                val (publicKeys, privateKeys) = keyPairs.getValue(keyReference)
                val encryptors = publicKeys.map { it.encryptor() }
                val decryptors = privateKeys.map { it.decryptor() }

                decryptors.forEach { decryptor ->
                    decryptor.decrypt(ciphertext, associatedData).assertContentEquals(plaintext)

                    encryptors.forEach { encryptor ->
                        decryptor.decrypt(encryptor.encrypt(plaintext, associatedData), associatedData).assertContentEquals(plaintext)
                    }
                }
            }
        }
    }
}
