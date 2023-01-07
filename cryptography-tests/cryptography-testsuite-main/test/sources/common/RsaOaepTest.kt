package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class RsaOaepTest {

    @OptIn(InsecureAlgorithm::class)
    @Test
    fun test() = runTest {
        supportedProviders.forEach { provider ->
            val algorithm = provider.get(RSA.OAEP)

            flow {
                println("RSA.OAEP: ${provider.name}")
                listOf(
                    2048.bits,
                    3072.bits,
                    4096.bits,
                ).forEach { keySize ->
                    println("|  keySize=${keySize.bits}")
                    listOf(
                        SHA1,
                        SHA256,
                        SHA384,
                        SHA512,
                    ).forEach { digest ->
                        //todo
                        val maxPlaintextSize = keySize.bytes - 2 - 2 * provider.get(digest).hasher().digestSize
                        println("   |  digest=$digest")
                        val keyGenerator = algorithm.keyPairGenerator(keySize, digest)

                        repeat(5) {
                            println("      |  keyPair.index=$it")
                            val keyPair = keyGenerator.generateKey()

                            repeat(5) { adIndex ->
                                val adSize = if (adIndex == 0) null else CryptographyRandom.nextInt(10000)
                                println("         |  associatedData.index=$adIndex, size=$adSize")

                                val associatedData = adSize?.let(CryptographyRandom::nextBytes)

                                repeat(5) { plaintextIndex ->
                                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                                    println("            |  plaintext.index=$plaintextIndex, size=$plaintextSize (max=$maxPlaintextSize)")
                                    val plaintext = CryptographyRandom.nextBytes(plaintextSize)

                                    val ciphertext = keyPair.publicKey.encryptor().encrypt(plaintext, associatedData)
                                    println("            |  ciphertext.index=$plaintextIndex, size=${ciphertext.size}")
                                    keyPair.privateKey.decryptor().decrypt(ciphertext, associatedData).assertContentEquals(plaintext)

                                    emit(
                                        RsaOaepTestData(
                                            digest = digest,
                                            derPrivateKey = keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.DER),
                                            jwkPrivateKey = keyPair.privateKey.encodeToIf(provider.isWebCrypto, RSA.PrivateKey.Format.JWK),
                                            derPublicKey = keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER),
                                            jwkPublicKey = keyPair.publicKey.encodeToIf(provider.isWebCrypto, RSA.PublicKey.Format.JWK),
                                            associatedData = associatedData,
                                            plaintext = plaintext,
                                            ciphertext = ciphertext
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
            }.collect { testData ->
                val publicKeys = algorithm.publicKeyDecoder(testData.digest).run {
                    listOfNotNull(
                        decodeFrom(RSA.PublicKey.Format.DER, testData.derPublicKey),
                        testData.jwkPublicKey?.let { decodeFromIf(provider.isWebCrypto, RSA.PublicKey.Format.JWK, it) }
                    )
                }

                val privateKeys = algorithm.privateKeyDecoder(testData.digest).run {
                    listOfNotNull(
                        decodeFrom(RSA.PrivateKey.Format.DER, testData.derPrivateKey),
                        testData.jwkPrivateKey?.let { decodeFromIf(provider.isWebCrypto, RSA.PrivateKey.Format.JWK, it) }
                    )
                }

                privateKeys.forEach { privateKey ->
                    privateKey.encodeTo(RSA.PrivateKey.Format.DER).assertContentEquals(testData.derPrivateKey)
                    testData.jwkPrivateKey?.let {
                        privateKey.encodeToIf(provider.isWebCrypto, RSA.PrivateKey.Format.JWK)?.assertContentEquals(it)
                    }

                    privateKey.decryptor()
                        .decrypt(testData.ciphertext, testData.associatedData)
                        .assertContentEquals(testData.plaintext)
                }

                publicKeys.forEach { publicKey ->
                    publicKey.encodeTo(RSA.PublicKey.Format.DER).assertContentEquals(testData.derPublicKey)
                    testData.jwkPublicKey?.let {
                        publicKey.encodeToIf(provider.isWebCrypto, RSA.PublicKey.Format.JWK)?.assertContentEquals(it)
                    }

                    val ciphertext = publicKey.encryptor().encrypt(testData.plaintext, testData.associatedData)
                    privateKeys.forEach { privateKey ->
                        privateKey.decryptor().decrypt(ciphertext, testData.associatedData).assertContentEquals(testData.plaintext)
                    }
                }
            }
        }
    }
}

class RsaOaepTestData(
    val digest: CryptographyAlgorithmId<Digest>,
    val derPrivateKey: ByteArray,
    val jwkPrivateKey: ByteArray?,
    val derPublicKey: ByteArray,
    val jwkPublicKey: ByteArray?,
    val associatedData: ByteArray?,
    val plaintext: ByteArray,
    val ciphertext: ByteArray,
)

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeToIf(supported: Boolean, format: KF): ByteArray? {
    return if (supported) encodeTo(format) else null
}

suspend fun <KF : KeyFormat, K : Key> KeyDecoder<KF, K>.decodeFromIf(supported: Boolean, format: KF, encoded: ByteArray): K? {
    return if (supported) decodeFrom(format, encoded) else null
}
