package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
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
                                            jwkPrivateKey = keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.JWK),
                                            derPublicKey = keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER),
                                            jwkPublicKey = keyPair.publicKey.encodeTo(RSA.PublicKey.Format.JWK),
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
            }.collect {
                val publicKeys = algorithm.publicKeyDecoder(it.digest).run {
                    listOfNotNull(
                        decodeFrom(RSA.PublicKey.Format.DER, it.derPublicKey),
                        it.jwkPublicKey?.let { decodeFrom(RSA.PublicKey.Format.JWK, it) }
                    )
                }

                val privateKeys = algorithm.privateKeyDecoder(it.digest).run {
                    listOfNotNull(
                        decodeFrom(RSA.PrivateKey.Format.DER, it.derPrivateKey),
                        it.jwkPrivateKey?.let { decodeFrom(RSA.PrivateKey.Format.JWK, it) }
                    )
                }

                privateKeys.forEach { privateKey ->
                    privateKey.encodeTo(RSA.PrivateKey.Format.DER).assertContentEquals(it.derPrivateKey)
                    it.jwkPrivateKey?.let { privateKey.encodeTo(RSA.PrivateKey.Format.JWK).assertContentEquals(it) }

                    privateKey.decryptor()
                        .decrypt(it.ciphertext, it.associatedData)
                        .assertContentEquals(it.plaintext)
                }

                publicKeys.forEach { publicKey ->
                    publicKey.encodeTo(RSA.PublicKey.Format.DER).assertContentEquals(it.derPublicKey)
                    it.jwkPublicKey?.let { publicKey.encodeTo(RSA.PublicKey.Format.JWK).assertContentEquals(it) }

                    val ciphertext = publicKey.encryptor().encrypt(it.plaintext, it.associatedData)
                    privateKeys.forEach { privateKey ->
                        privateKey.decryptor().decrypt(ciphertext, it.associatedData).assertContentEquals(it.plaintext)
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
