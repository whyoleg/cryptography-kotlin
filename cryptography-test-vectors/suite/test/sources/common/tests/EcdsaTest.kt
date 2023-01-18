package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*
import kotlinx.serialization.*

private const val keyIterations = 5
private const val signatureIterations = 5
private const val maxDataSize = 10000

private inline fun generateCurves(block: (curve: EC.Curve) -> Unit) {
    generate(block, EC.Curve.P256, EC.Curve.P384, EC.Curve.P521)
}

//TODO: different signature sizes JVM vs nodejs/browser (truncated)
class EcdsaTest : TestVectorTest<ECDSA>(ECDSA) {
    @Serializable
    private data class KeyParameters(val curveName: String) : TestVectorParameters {
        val curve
            get() = when (curveName) {
                EC.Curve.P256.name -> EC.Curve.P256
                EC.Curve.P384.name -> EC.Curve.P384
                EC.Curve.P521.name -> EC.Curve.P521
                else               -> error("Unknown curve: $curveName")
            }
    }

    @Serializable
    private data class SignatureParameters(val digest: String) : TestVectorParameters

    override suspend fun generate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: ECDSA) {
        val digests = buildList {
            generateDigests { digest, _ ->
                val id = api.signatures.saveParameters(SignatureParameters(digest.name))
                add(id to digest)
            }
        }
        generateCurves { curve ->
            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))
            algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
                val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(
                    public = KeyData {
                        put(StringKeyFormat.DER, keyPair.publicKey.encodeTo(EC.PublicKey.Format.DER))
                        if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.publicKey.encodeTo(EC.PublicKey.Format.JWK))
                    },
                    private = KeyData {
                        put(StringKeyFormat.DER, keyPair.privateKey.encodeTo(EC.PrivateKey.Format.DER))
                        if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.privateKey.encodeTo(EC.PrivateKey.Format.JWK))
                    }
                ))

                digests.forEach { (signatureParametersId, digest) ->
                    logging.log("digest = $digest")
                    val signer = keyPair.privateKey.signatureGenerator(digest)
                    val verifier = keyPair.publicKey.signatureVerifier(digest)

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

    override suspend fun validate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: ECDSA) {
        val keyPairs = buildMap {
            api.keyPairs.getParameters<KeyParameters> { keyParameters, parametersId ->
                val privateKeyDecoder = algorithm.privateKeyDecoder(keyParameters.curve)
                val publicKeyDecoder = algorithm.publicKeyDecoder(keyParameters.curve)

                api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference ->
                    val publicKeys = publicKeyDecoder.decodeFrom(public.formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.DER -> EC.PublicKey.Format.DER
                            StringKeyFormat.JWK -> EC.PublicKey.Format.JWK.takeIf { provider.supportsJwk }
                            else                -> error("Unsupported key format: $stringFormat") //TODO
                        }
                    }
                    publicKeys.forEach { publicKey ->
                        public.formats[StringKeyFormat.DER]?.let { bytes ->
                            publicKey.encodeTo(EC.PublicKey.Format.DER).assertContentEquals(bytes)
                        }
                    }
                    val privateKeys = privateKeyDecoder.decodeFrom(private.formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.DER -> EC.PrivateKey.Format.DER
                            StringKeyFormat.JWK -> EC.PrivateKey.Format.JWK.takeIf { provider.supportsJwk }
                            else                -> error("Unsupported key format: $stringFormat") //TODO
                        }
                    }
                    privateKeys.forEach { privateKey ->
                        private.formats[StringKeyFormat.DER]?.let { bytes ->
                            privateKey.encodeTo(EC.PrivateKey.Format.DER).assertContentEquals(bytes)
                        }
                    }
                    put(keyReference, publicKeys to privateKeys)
                }
            }
        }

        api.signatures.getParameters<SignatureParameters> { (digestName), parametersId ->
            val digest = digest(digestName)
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                val (publicKeys, privateKeys) = keyPairs.getValue(keyReference)
                val verifiers = publicKeys.map { it.signatureVerifier(digest) }
                val generators = privateKeys.map { it.signatureGenerator(digest) }

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
