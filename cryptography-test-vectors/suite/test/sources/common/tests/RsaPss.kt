package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*
import kotlinx.serialization.*

private const val keyIterations = 5
private const val saltIterations = 5
private const val maxSaltSize = 100
private const val maxDataSize = 10000
private const val signatureIterations = 5
private fun CryptographyProvider.supportsDigest(digest: CryptographyAlgorithmId<Digest>, logging: TestLoggingContext): Boolean {
    val jvmVersion = currentPlatformJvmVersion ?: return true

    return skipUnsupported(
        feature = "Any RSA-PSS digest",
        supports = jvmVersion >= 17 || digest == SHA1, // JVM support digests other than SHA1 since 17
        logging = logging
    )
}

private inline fun generateKeySizes(block: (keySize: BinarySize) -> Unit) {
    listOf(2048.bits, 3072.bits, 4096.bits).forEach { keySize ->
        block(keySize)
    }
}

class RsaPssTest : TestVectorTest<RSA.PSS>(RSA.PSS) {

    @Serializable
    private data class KeyParameters(val keySizeBits: Int, val digest: String) : TestVectorParameters

    @Serializable
    private data class SignatureParameters(val saltSizeBytes: Int) : TestVectorParameters

    override suspend fun generate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: RSA.PSS) {
        val saltSizes = buildList {
            repeat(saltIterations) {
                val saltSize = CryptographyRandom.nextInt(maxSaltSize)
                val id = api.ciphers.saveParameters(SignatureParameters(saltSize))
                add(id to saltSize.bytes)
            }
        }

        generateKeySizes { keySize ->
            generateDigests { digest, _ ->
                if (!provider.supportsDigest(digest, logging)) return@generateDigests

                val keyParametersId = api.keyPairs.saveParameters(KeyParameters(keySize.inBits, digest.name))
                algorithm.keyPairGenerator(keySize, digest).generateKeys(keyIterations) { keyPair ->
                    val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(
                        public = KeyData {
                            put(StringKeyFormat.DER, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER))
                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.JWK))
                        },
                        private = KeyData {
                            put(StringKeyFormat.DER, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.DER))
                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.JWK))
                        }
                    ))

                    saltSizes.forEach { (signatureParametersId, saltSize) ->
                        logging.log("salt.size      = ${saltSize.inBytes}")

                        val signer = keyPair.privateKey.signatureGenerator(saltSize)
                        val verifier = keyPair.publicKey.signatureVerifier(saltSize)

                        repeat(signatureIterations) {
                            val dataSize = CryptographyRandom.nextInt(maxDataSize)
                            logging.log("data.size      = $dataSize")
                            val data = CryptographyRandom.nextBytes(dataSize)
                            val signature = signer.generateSignature(data)
                            logging.log("signature.size = ${signature.size}")

                            verifier.verifySignature(data, signature).assertTrue()

                            api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                        }
                    }
                }
            }
        }
    }

    override suspend fun validate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: RSA.PSS) {
        val keyPairs = buildMap {
            api.keys.getParameters<KeyParameters> { (_, digestName), parametersId ->
                val digest = digest(digestName)
                if (!provider.supportsDigest(digest, logging)) return@getParameters

                val privateKeyDecoder = algorithm.privateKeyDecoder(digest)
                val publicKeyDecoder = algorithm.publicKeyDecoder(digest)

                api.keys.getData<KeyPairData>(parametersId) { (public, private), keyReference ->
                    val publicKeys = publicKeyDecoder.decodeFrom(public.formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.DER -> RSA.PublicKey.Format.DER
                            StringKeyFormat.JWK -> RSA.PublicKey.Format.JWK.takeIf { provider.supportsJwk }
                            else                -> error("Unsupported key format: $stringFormat") //TODO
                        }
                    }
                    publicKeys.forEach { publicKey ->
                        public.formats[StringKeyFormat.DER]?.let { bytes ->
                            publicKey.encodeTo(RSA.PublicKey.Format.DER).assertContentEquals(bytes)
                        }
                    }
                    val privateKeys = privateKeyDecoder.decodeFrom(private.formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.DER -> RSA.PrivateKey.Format.DER
                            StringKeyFormat.JWK -> RSA.PrivateKey.Format.JWK.takeIf { provider.supportsJwk }
                            else                -> error("Unsupported key format: $stringFormat") //TODO
                        }
                    }
                    privateKeys.forEach { privateKey ->
                        private.formats[StringKeyFormat.DER]?.let { bytes ->
                            privateKey.encodeTo(RSA.PrivateKey.Format.DER).assertContentEquals(bytes)
                        }
                    }
                    put(keyReference, publicKeys to privateKeys)
                }
            }
        }

        api.signatures.getParameters<SignatureParameters> { (saltSizeBytes), parametersId ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                val (publicKeys, privateKeys) = keyPairs.getValue(keyReference)
                val verifiers = publicKeys.map { it.signatureVerifier(saltSizeBytes.bytes) }
                val generators = privateKeys.map { it.signatureGenerator(saltSizeBytes.bytes) }

                verifiers.forEach { verifier ->
                    verifier.verifySignature(data, signature).assertTrue()

                    generators.forEach { generator ->
                        verifier.verifySignature(data, generator.generateSignature(data)).assertTrue()
                    }
                }
            }
        }
    }
}
