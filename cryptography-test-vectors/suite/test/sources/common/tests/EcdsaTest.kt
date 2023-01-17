package dev.whyoleg.cryptography.test.vectors.suite.tests

//import dev.whyoleg.cryptography.algorithms.*
//import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
//import dev.whyoleg.cryptography.algorithms.digest.*
//import dev.whyoleg.cryptography.random.*
//import kotlinx.coroutines.*
//import kotlinx.coroutines.flow.*
//import kotlinx.coroutines.test.*
//import kotlin.test.*
//
//class EcdsaTest {
//    //TODO: different signature sizes JVM vs nodejs/browser (truncated)
//    @OptIn(ExperimentalCoroutinesApi::class, InsecureAlgorithm::class)
//    @Test
//    fun test() = runTest {
//        supportedProviders.forEach { provider ->
//            //gen key1-1, key1-2
//            //gen key2-1, key2-2
//            //combine pairs
//            //derive shared
//            //compare shared
//
////            provider.get(ECDH)
////                .keyPairGenerator(EC.Curve.P521)
////                .generateKey()
////                .privateKey
////                .derivative()
////                .deriveSharedSecretFrom()
//
//            val algorithm = provider.get(ECDSA)
//
//            flow {
//                println("ECDSA: ${provider.name}")
//                listOf(
//                    EC.Curve.P256,
//                    EC.Curve.P384,
//                    EC.Curve.P521,
//                ).forEach { curve ->
//                    println("|  curve=${curve.name}")
//
//                    val keyGenerator = algorithm.keyPairGenerator(curve)
//
//                    repeat(5) { keyIndex ->
//                        println("   |  keyPair.index=$keyIndex")
//                        val keyPair = keyGenerator.generateKey()
//
//                        listOf(
//                            SHA1,
//                            SHA256,
//                            SHA384,
//                            SHA512,
//                        ).forEach { digest ->
//                            println("      |  digest=$digest")
//
//                            val signer = keyPair.privateKey.signatureGenerator(digest)
//                            val verifier = keyPair.publicKey.signatureVerifier(digest)
//
//                            repeat(5) { dataIndex ->
//                                val dataSize = CryptographyRandom.nextInt(10000)
//
//                                println("         |  data.index=$dataIndex, size=$dataSize")
//                                val data = CryptographyRandom.nextBytes(dataSize)
//
//                                val signature = signer.generateSignature(data)
//                                println("         |  signature.index=$dataIndex, size=${signature.size}")
//                                verifier.verifySignature(data, signature).assertTrue()
//
//                                emit(
//                                    EcdsaTestData(
//                                        curve = curve,
//                                        digest = digest,
//                                        derPrivateKey = keyPair.privateKey.encodeTo(EC.PrivateKey.Format.DER),
//                                        jwkPrivateKey = keyPair.privateKey.encodeToIf(provider.isWebCrypto, EC.PrivateKey.Format.JWK),
//                                        derPublicKey = keyPair.publicKey.encodeTo(EC.PublicKey.Format.DER),
//                                        jwkPublicKey = keyPair.publicKey.encodeToIf(provider.isWebCrypto, EC.PublicKey.Format.JWK),
//                                        data = data,
//                                        signature = signature
//                                    )
//                                )
//                            }
//                        }
//                    }
//                }
//            }.collect { testData ->
//                val publicKeys = algorithm.publicKeyDecoder(testData.curve).run {
//                    listOfNotNull(
//                        decodeFrom(EC.PublicKey.Format.DER, testData.derPublicKey),
//                        testData.jwkPublicKey?.let { decodeFromIf(provider.isWebCrypto, EC.PublicKey.Format.JWK, it) }
//                    )
//                }
//
//                val privateKeys = algorithm.privateKeyDecoder(testData.curve).run {
//                    listOfNotNull(
//                        decodeFrom(EC.PrivateKey.Format.DER, testData.derPrivateKey),
//                        testData.jwkPrivateKey?.let { decodeFromIf(provider.isWebCrypto, EC.PrivateKey.Format.JWK, it) }
//                    )
//                }
//
//                privateKeys.forEach { privateKey ->
//                    privateKey.encodeTo(EC.PrivateKey.Format.DER).assertContentEquals(testData.derPrivateKey)
//                    testData.jwkPrivateKey?.let {
//                        privateKey.encodeToIf(provider.isWebCrypto, EC.PrivateKey.Format.JWK)?.assertContentEquals(it)
//                    }
//
//                    val signature = privateKey.signatureGenerator(testData.digest).generateSignature(testData.data)
//                    publicKeys.forEach { publicKey ->
//                        publicKey.signatureVerifier(testData.digest).verifySignature(testData.data, signature).assertTrue()
//                    }
//                }
//
//                publicKeys.forEach { publicKey ->
//                    publicKey.encodeTo(EC.PublicKey.Format.DER).assertContentEquals(testData.derPublicKey)
//                    testData.jwkPublicKey?.let {
//                        publicKey.encodeToIf(provider.isWebCrypto, EC.PublicKey.Format.JWK)?.assertContentEquals(it)
//                    }
//
//                    publicKey.signatureVerifier(testData.digest)
//                        .verifySignature(testData.data, testData.signature)
//                        .assertTrue()
//                }
//            }
//        }
//    }
//}
//
//class EcdsaTestData(
//    val curve: EC.Curve,
//    val digest: CryptographyAlgorithmId<Digest>,
//    val derPrivateKey: ByteArray,
//    val jwkPrivateKey: ByteArray?,
//    val derPublicKey: ByteArray,
//    val jwkPublicKey: ByteArray?,
//    val data: ByteArray,
//    val signature: ByteArray,
//)
