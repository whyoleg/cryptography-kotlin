package dev.whyoleg.cryptography.test.vectors.suite.tests

//import dev.whyoleg.cryptography.BinarySize.Companion.bits
//import dev.whyoleg.cryptography.BinarySize.Companion.bytes
//import dev.whyoleg.cryptography.algorithms.*
//import dev.whyoleg.cryptography.algorithms.asymmetric.*
//import dev.whyoleg.cryptography.algorithms.digest.*
//import dev.whyoleg.cryptography.materials.key.*
//import dev.whyoleg.cryptography.provider.*
//import dev.whyoleg.cryptography.random.*
//import kotlinx.coroutines.*
//import kotlinx.coroutines.flow.*
//import kotlinx.coroutines.test.*
//import kotlin.test.*
//
//@OptIn(ExperimentalCoroutinesApi::class)
//class RsaPssTest {
//
//    @OptIn(InsecureAlgorithm::class)
//    @Test
//    fun test() = runTest {
//        supportedProviders.forEach { provider ->
//            val algorithm = provider.get(RSA.PSS)
//
//            flow {
//                println("RSA.PSS: ${provider.name}")
//                listOf(
//                    2048.bits,
//                    3072.bits,
//                    4096.bits,
//                ).forEach { keySize ->
//                    println("|  keySize=${keySize.bits}")
//                    listOf(
//                        SHA1,
//                        SHA256,
//                        SHA384,
//                        SHA512,
//                    ).forEach { digest ->
//                        println("   |  digest=$digest")
//                        val keyGenerator = algorithm.keyPairGenerator(keySize, digest)
//
//                        repeat(5) { keyIndex ->
//                            println("      |  keyPair.index=$keyIndex")
//                            val keyPair = keyGenerator.generateKey()
//
//                            repeat(5) { saltIndex ->
//                                val saltSize = CryptographyRandom.nextInt(100)
//                                println("         |  salt.index=$saltIndex, size=$saltSize")
//
//                                val signer = keyPair.privateKey.signatureGenerator(saltSize.bytes)
//                                val verifier = keyPair.publicKey.signatureVerifier(saltSize.bytes)
//
//                                repeat(5) { dataIndex ->
//                                    val dataSize = CryptographyRandom.nextInt(10000)
//                                    println("            |  data.index=$dataIndex, size=$dataSize")
//                                    val data = CryptographyRandom.nextBytes(dataSize)
//
//                                    val signature = signer.generateSignature(data)
//                                    println("            |  signature.index=$dataIndex, size=${signature.size}")
//                                    verifier.verifySignature(data, signature).assertTrue()
//
//                                    emit(
//                                        RsaPssTestData(
//                                            digest = digest,
//                                            derPrivateKey = keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.DER),
//                                            jwkPrivateKey = keyPair.privateKey.encodeToIf(provider.isWebCrypto, RSA.PrivateKey.Format.JWK),
//                                            derPublicKey = keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER),
//                                            jwkPublicKey = keyPair.publicKey.encodeToIf(provider.isWebCrypto, RSA.PublicKey.Format.JWK),
//                                            saltSize = saltSize,
//                                            data = data,
//                                            signature = signature
//                                        )
//                                    )
//                                }
//                            }
//                        }
//                    }
//                }
//            }.collect { testData ->
//                val publicKeys = algorithm.publicKeyDecoder(testData.digest).run {
//                    listOfNotNull(
//                        decodeFrom(RSA.PublicKey.Format.DER, testData.derPublicKey),
//                        testData.jwkPublicKey?.let { decodeFromIf(provider.isWebCrypto, RSA.PublicKey.Format.JWK, it) }
//                    )
//                }
//
//                val privateKeys = algorithm.privateKeyDecoder(testData.digest).run {
//                    listOfNotNull(
//                        decodeFrom(RSA.PrivateKey.Format.DER, testData.derPrivateKey),
//                        testData.jwkPrivateKey?.let { decodeFromIf(provider.isWebCrypto, RSA.PrivateKey.Format.JWK, it) }
//                    )
//                }
//
//                privateKeys.forEach { privateKey ->
//                    privateKey.encodeTo(RSA.PrivateKey.Format.DER).assertContentEquals(testData.derPrivateKey)
//                    testData.jwkPrivateKey?.let {
//                        privateKey.encodeToIf(provider.isWebCrypto, RSA.PrivateKey.Format.JWK)?.assertContentEquals(it)
//                    }
//
//                    val signature = privateKey.signatureGenerator(testData.saltSize.bytes).generateSignature(testData.data)
//                    publicKeys.forEach { publicKey ->
//                        publicKey.signatureVerifier(testData.saltSize.bytes).verifySignature(testData.data, signature).assertTrue()
//                    }
//                }
//
//                publicKeys.forEach { publicKey ->
//                    publicKey.encodeTo(RSA.PublicKey.Format.DER).assertContentEquals(testData.derPublicKey)
//                    testData.jwkPublicKey?.let {
//                        publicKey.encodeToIf(provider.isWebCrypto, RSA.PublicKey.Format.JWK)?.assertContentEquals(it)
//                    }
//
//                    publicKey.signatureVerifier(testData.saltSize.bytes)
//                        .verifySignature(testData.data, testData.signature)
//                        .assertTrue()
//                }
//            }
//        }
//    }
//}
//
//class RsaPssTestData(
//    val digest: CryptographyAlgorithmId<Digest>,
//    val derPrivateKey: ByteArray,
//    val jwkPrivateKey: ByteArray?,
//    val derPublicKey: ByteArray,
//    val jwkPublicKey: ByteArray?,
//    val saltSize: Int,
//    val data: ByteArray,
//    val signature: ByteArray,
//)
