package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
import dev.whyoleg.cryptography.algorithms.digest.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.test.*

//keys:
//JS-BROWSER-WebCrypto-ECDH-P256-PUBLIC-JWK-1
//JS-BROWSER-WebCrypto-ECDH-P256-PUBLIC-JWK-2

//JS-BROWSER-WebCrypto-AES-GCM-256-JWK-1

class EcdhTest {

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun test() = runTest {
        supportedProviders.forEach { provider ->
            val algorithm = provider.get(ECDH)

            flow {
                println("ECDH: ${provider.name}")
                listOf(
                    EC.Curve.P256,
                    EC.Curve.P384,
                    EC.Curve.P521,
                ).forEach { curve ->
                    println("|  curve=${curve.name}")

                    val keyGenerator = algorithm.keyPairGenerator(curve)

                    repeat(5) { keyIndex ->
                        println("   |  keyPair.index=$keyIndex")
                        val keyPair = keyGenerator.generateKey()

                        emit(
                            EcdhTestData(
                                curve = curve,
                                derPrivateKey = keyPair.privateKey.encodeTo(EC.PrivateKey.Format.DER),
                                jwkPrivateKey = keyPair.privateKey.encodeToIf(provider.isWebCrypto, EC.PrivateKey.Format.JWK),
                                derPublicKey = keyPair.publicKey.encodeTo(EC.PublicKey.Format.DER),
                                jwkPublicKey = keyPair.publicKey.encodeToIf(provider.isWebCrypto, EC.PublicKey.Format.JWK),
                            )
                        )
                    }
                }
            }.toList().groupBy { it.curve }.let { list ->
                list.forEach { (curve, data) ->
                    val publicKeyDecoder = algorithm.publicKeyDecoder(curve)
                    val privateKeyDecoder = algorithm.privateKeyDecoder(curve)

                    data.forEach { testData1 ->
                        data.forEach { testData2 ->
                            if (testData1 == testData2) return@forEach

                            suspend fun test(
                                public: EncodedKey,
                                private: EncodedKey,
                            ) {
                                publicKeyDecoder
                                    .decodeFrom(EC.PublicKey.Format.DER, public.data)
                                    .derivative()
                                    .deriveSharedSecretFrom(EC.PrivateKey.Format.DER, private.data)
                                    .assertContentEquals(
                                        privateKeyDecoder
                                            .decodeFrom(EC.PrivateKey.Format.DER, private.data)
                                            .derivative()
                                            .deriveSharedSecretFrom(EC.PublicKey.Format.DER, public.data)
                                    )
                            }

                            listOf(
                                EncodedKey("der", testData1.derPublicKey),
                                EncodedKey("jwk", testData1.jwkPublicKey!!)
                            ).forEach { pubK1 ->
                                listOf(
                                    EncodedKey("der", testData2.derPrivateKey),
                                    EncodedKey("jwk", testData2.jwkPrivateKey!!)
                                ).forEach { privK2 ->

                                }
                            }

                            val privK1 = listOf(
                                EncodedKey("der", testData1.derPrivateKey),
                                EncodedKey("jwk", testData1.jwkPrivateKey!!)
                            )

                            val pubK2 = listOf(
                                EncodedKey("der", testData2.derPublicKey),
                                EncodedKey("jwk", testData2.jwkPublicKey!!)
                            )

                            val privK2 =


                            val s1 = publicKeyDecoder.decodeFrom(EC.PublicKey.Format.DER, testData1.derPublicKey)
                                .derivative()
                                .deriveSharedSecretFrom(EC.PrivateKey.Format.DER, testData2.derPrivateKey)

                            val s4 = privateKeyDecoder.decodeFrom(EC.PrivateKey.Format.DER, testData2.derPrivateKey)
                                .derivative()
                                .deriveSharedSecretFrom(EC.PublicKey.Format.DER, testData1.derPublicKey)

                            val s2 = publicKeyDecoder.decodeFrom(EC.PublicKey.Format.DER, testData2.derPublicKey)
                                .derivative()
                                .deriveSharedSecretFrom(EC.PrivateKey.Format.DER, testData1.derPrivateKey)

                            val s3 = privateKeyDecoder.decodeFrom(EC.PrivateKey.Format.DER, testData1.derPrivateKey)
                                .derivative()
                                .deriveSharedSecretFrom(EC.PublicKey.Format.DER, testData2.derPublicKey)

                            s1.assertContentEquals(s2)
                            s1.assertContentEquals(s3)
                            s1.assertContentEquals(s4)
                        }
                    }
                }
            }
        }
    }
}

class EcdhTestData(
    val curve: EC.Curve,
    val derPrivateKey: ByteArray,
    val jwkPrivateKey: ByteArray?,
    val derPublicKey: ByteArray,
    val jwkPublicKey: ByteArray?,
)

class EncodedKey(
    val format: String,
    val data: ByteArray,
)
