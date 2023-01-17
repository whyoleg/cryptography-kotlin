package dev.whyoleg.cryptography.test.suite.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.api.*
import dev.whyoleg.cryptography.test.suite.*
import dev.whyoleg.cryptography.test.suite.generators.*

private const val keyIterations = 5
private const val associatedDataIterations = 5
private const val maxAssociatedDataSize = 10000
private const val cipherIterations = 5

private inline fun keySizes(block: (keySize: BinarySize, keyParams: String) -> Unit) {
    listOf(2048.bits, 3072.bits, 4096.bits).forEach { keySize ->
        block(keySize, "${keySize.bits}bits")
    }
}

//key-pairs/RSA-PSS |2048bits+SHA-256| |salt=5, ad, data, signature|

//RSA-PSS:
// - key size - static
// - digest - static
// - publicExponent - dynamic

// - salt size - dynamic
// - associated data - dynamic

// key-pairs
//  - create
//  - get by id + params
//  - list params


//filesystem:
//rsa-pss | data.json - fake
//rsa-pss | key-pairs/key-pair-params-1
//rsa-pss | key-pairs/key-pair-params-1/meta.json
//rsa-pss | key-pairs/key-pair-params-1/data/key-pair-1
//rsa-pss | key-pairs/key-pair-params-1/data/key-pair-1 | data.json (provider, platform, data)
//rsa-pss | key-pairs/key-pair-params-1/data/key-pair-1 | signatures/signature-params-1
//rsa-pss | key-pairs/key-pair-params-1/data/key-pair-1 | signatures/signature-params-1/data.json
//rsa-pss | key-pairs/key-pair-params-1/data/key-pair-1 | signatures/signature-params-1/signature-1/data.json

//routes
//POST | rsa-pss/key-pairs - create param - return id
//GET  | rsa-pss/key-pairs - list params - return list of params
//POST | rsa-pss/key-pairs/kpp-1/data - create key-pair - return id
//GET  | rsa-pss/key-pairs/kpp-1/data - list key-pairs - return list of key-pairs

//POST | rsa-pss/key-pairs/kpp-1/data/kp-1/signatures - create signature params - return id
//GET  | rsa-pss/key-pairs/kpp-1/data/kp-1/signatures - list signature params- return list of signatures
//POST | rsa-pss/key-pairs/kpp-1/data/kp-1/signatures/sp-1/data - create signature - return id
//GET  | rsa-pss/key-pairs/kpp-1/data/kp-1/signatures/sp-1/data - get signature - return signature

//RSA-PSS/
//       /key-pairs/meta/ID
//                         /ID - key id
//                            /signatures/meta/ID
//                         /signatures/data/

/**
 * requirements: (tree)
 * - entities params (create, get-all)
 * - entities data (create, get-all)
 * - sub-entities params (create, get-all)
 * - sub-entities data (create, get-all)
 */

private val generate = TestAction { api, provider ->
    val algorithm = provider.get(RSA.OAEP)

    keySizes { keySize, keyParams ->
        digests { digest, digestSize ->
            val maxPlaintextSize = keySize.bytes - 2 - 2 * digestSize

            algorithm.keyPairGenerator(keySize, digest).generateKeys(keyIterations) { keyPair ->
                val keyId = api.keyPairs.save(
                    algorithm.id.name,
                    keyParams + digest.name,
                    KeyPairData(
                        public = KeyData {
                            put(StringKeyFormat.DER, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER))
                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.JWK))
                        },
                        private = KeyData {
                            put(StringKeyFormat.DER, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.DER))
                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.JWK))
                        }
                    )
                )

                repeat(associatedDataIterations) { adIndex ->
                    val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                    println("generate: associatedData.size  = $associatedDataSize")
                    val associatedData = associatedDataSize?.let(CryptographyRandom::nextBytes)

                    repeat(cipherIterations) {
                        val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                        println("generate: plaintext.size  = $plaintextSize")
                        val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                        val ciphertext = keyPair.publicKey.encryptor().encrypt(plaintext, associatedData)
                        println("generate: ciphertext.size  = ${ciphertext.size}")

                        keyPair.privateKey.decryptor().decrypt(ciphertext, associatedData).assertContentEquals(plaintext)

                        api.ciphers.save(
                            algorithm = algorithm.id.name,
                            params = keyParams + digest.name, //TODO!!!
                            data = CipherData(
                                keyId = keyId,
                                keyParams = keyParams + digest.name,
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
}

private val validate = TestAction { api, provider ->
    val algorithm = provider.get(RSA.OAEP)


    keySizes { keySize, keyParams ->
        digests { digest, digestSize ->

            api.ciphers.getAll(
                algorithm = algorithm.id.name,
                params = keyParams + digest.name
            ).forEach { (cipherData) ->
                val keyPairData = api.keyPairs.get(
                    algorithm = algorithm.id.name,
                    params = cipherData.keyParams,
                    id = cipherData.keyId
                ).data

                val privateKeyDecoder = algorithm.privateKeyDecoder(digest)
                val publicKeyDecoder = algorithm.publicKeyDecoder(digest)

                keyPairData.private.formats.forEach { (privateKeyStringFormat, privateKeyBuffer) ->
                    val privateKey = privateKeyDecoder.decodeFrom(
                        format = when (privateKeyStringFormat) {
                            StringKeyFormat.DER -> RSA.PrivateKey.Format.DER
                            StringKeyFormat.JWK -> RSA.PrivateKey.Format.JWK.takeIf { provider.supportsJwk }
                            else                -> error("Unsupported key format: $privateKeyStringFormat") //TODO
                        },
                        input = privateKeyBuffer
                    ) ?: return@forEach

                    keyPairData.private.formats[StringKeyFormat.DER]?.let { bytes ->
                        privateKey.encodeTo(RSA.PrivateKey.Format.DER).assertContentEquals(bytes)
                    }

                    privateKey.decryptor()
                        .decrypt(cipherData.ciphertext, cipherData.associatedData)
                        .assertContentEquals(cipherData.plaintext)

                    keyPairData.public.formats.forEach { (publicKeyStringFormat, publicKeyBuffer) ->
                        val publicKey = publicKeyDecoder.decodeFrom(
                            format = when (publicKeyStringFormat) {
                                StringKeyFormat.DER -> RSA.PublicKey.Format.DER
                                StringKeyFormat.JWK -> RSA.PublicKey.Format.JWK.takeIf { provider.supportsJwk }
                                else                -> error("Unsupported key format: $privateKeyStringFormat") //TODO
                            },
                            input = publicKeyBuffer
                        ) ?: return@forEach

                        keyPairData.public.formats[StringKeyFormat.DER]?.let { bytes ->
                            publicKey.encodeTo(RSA.PublicKey.Format.DER).assertContentEquals(bytes)
                        }

                        privateKey.decryptor().decrypt(
                            publicKey.encryptor().encrypt(cipherData.plaintext, cipherData.associatedData),
                            cipherData.associatedData
                        ).assertContentEquals(cipherData.plaintext)
                    }
                }
            }
        }
    }
}

val rsaOaep = TestSuite("RSA-OAEP", generate = generate, validate = validate)
