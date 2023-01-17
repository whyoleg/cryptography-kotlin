package dev.whyoleg.cryptography.test.vectors.suite.tests

//private const val keyIterations = 5
//private const val saltIterations = 5
//private const val maxSaltSize = 100
//private const val maxDataSize = 10000
//private const val signatureIterations = 5
//
//private inline fun keySizes(block: (keySize: BinarySize, keyParams: String) -> Unit) {
//    listOf(2048.bits, 3072.bits, 4096.bits).forEach { keySize ->
//        block(keySize, "${keySize.bits}bits")
//    }
//}
//
//private val generate = TestAction { api, provider ->
//    val algorithm = provider.get(RSA.PSS)
//
//    keySizes { keySize, keyParams ->
//        digests { digest, digestSize ->
//            val keyGenerator = algorithm.keyPairGenerator(keySize, digest)
//
//            repeat(keyIterations) {
//                val keyPair = keyGenerator.generateKey()
//
//                val keyId = api.keyPairs.save(
//                    algorithm.id.name,
//                    keyParams + digest.name,
//                    KeyPairData(
//                        public = KeyData {
//                            put(StringKeyFormat.DER, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER))
//                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.JWK))
//                        },
//                        private = KeyData {
//                            put(StringKeyFormat.DER, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.DER))
//                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.JWK))
//                        }
//                    )
//                )
//
//                repeat(saltIterations) {
//                    val saltSize = CryptographyRandom.nextInt(maxSaltSize)
//                    println("generate: salt.size  = $saltSize")
//
//                    val signer = keyPair.privateKey.signatureGenerator(saltSize.bytes)
//                    val verifier = keyPair.publicKey.signatureVerifier(saltSize.bytes)
//
//                    repeat(signatureIterations) {
//                        val dataSize = CryptographyRandom.nextInt(maxDataSize)
//                        println("generate: data.size  = $dataSize")
//                        val data = CryptographyRandom.nextBytes(dataSize)
//                        val signature = signer.generateSignature(data)
//                        println("generate: signature.size  = ${signature.size}")
//
//                        verifier.verifySignature(data, signature).assertTrue()
//
//                        api.signatures.save(
//                            algorithm = algorithm.id.name,
//                            params = keyParams + digest.name + "${saltSize}bytes", //TODO!!!
//                            data = SignatureData(
//                                keyId = keyId,
//                                keyParams = keyParams + digest.name,
//                                data = data,
//                                signature = signature
//                            )
//                        )
//                    }
//                }
//            }
//        }
//    }
//}
//
//private val validate = TestAction { api, provider ->
//    val algorithm = provider.get(RSA.PSS)
//
//    keySizes { keySize, keyParams ->
//        digests { digest, digestSize ->
//
//            api.signatures.getAll(
//                algorithm = algorithm.id.name,
//                params = keyParams + digest.name
//            ).forEach { (signatureData) ->
//                val keyPairData = api.keyPairs.get(
//                    algorithm = algorithm.id.name,
//                    params = signatureData.keyParams,
//                    id = signatureData.keyId
//                ).data
//
//                val privateKeyDecoder = algorithm.privateKeyDecoder(digest)
//                val publicKeyDecoder = algorithm.publicKeyDecoder(digest)
//
//                keyPairData.private.formats.forEach { (privateKeyStringFormat, privateKeyBuffer) ->
//                    val privateKey = privateKeyDecoder.decodeFrom(
//                        format = when (privateKeyStringFormat) {
//                            StringKeyFormat.DER -> RSA.PrivateKey.Format.DER
//                            StringKeyFormat.JWK -> RSA.PrivateKey.Format.JWK.takeIf { provider.supportsJwk }
//                            else                -> error("Unsupported key format: $privateKeyStringFormat") //TODO
//                        },
//                        input = privateKeyBuffer
//                    ) ?: return@forEach
//
//                    keyPairData.private.formats[StringKeyFormat.DER]?.let { bytes ->
//                        privateKey.encodeTo(RSA.PrivateKey.Format.DER).assertContentEquals(bytes)
//                    }
//
//                    privateKey.decryptor()
//                        .decrypt(signatureData.ciphertext, signatureData.associatedData)
//                        .assertContentEquals(signatureData.plaintext)
//
//                    keyPairData.public.formats.forEach { (publicKeyStringFormat, publicKeyBuffer) ->
//                        val publicKey = publicKeyDecoder.decodeFrom(
//                            format = when (publicKeyStringFormat) {
//                                StringKeyFormat.DER -> RSA.PublicKey.Format.DER
//                                StringKeyFormat.JWK -> RSA.PublicKey.Format.JWK.takeIf { provider.supportsJwk }
//                                else                -> error("Unsupported key format: $privateKeyStringFormat") //TODO
//                            },
//                            input = publicKeyBuffer
//                        ) ?: return@forEach
//
//                        keyPairData.public.formats[StringKeyFormat.DER]?.let { bytes ->
//                            publicKey.encodeTo(RSA.PublicKey.Format.DER).assertContentEquals(bytes)
//                        }
//
//                        privateKey.decryptor().decrypt(
//                            publicKey.encryptor().encrypt(signatureData.plaintext, signatureData.associatedData),
//                            signatureData.associatedData
//                        ).assertContentEquals(signatureData.plaintext)
//                    }
//                }
//            }
//        }
//    }
//}
//
//val rsaPss = TestSuite("RSA-PSS", generate = generate, validate = validate)
