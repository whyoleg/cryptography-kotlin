package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.test.utils.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 5

private inline fun generateKeySizes(block: (keySize: BinarySize) -> Unit) {
    generate(block, 2048.bits, 3072.bits, 4096.bits)
}

abstract class RsaBasedTest<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>, A : RSA<PublicK, PrivateK, KP>>(
    algorithmId: CryptographyAlgorithmId<A>,
) : CompatibilityTest<A>(algorithmId) {

    @Serializable
    protected data class KeyParameters(
        val keySizeBits: Int,
        val digest: String,
        val digestSize: Int,
    ) : TestParameters {
        val keySize get() = keySizeBits.bits
    }

    protected suspend fun CompatibilityTestContext<A>.generateKeys(
        block: suspend (keyPair: KP, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        generateKeySizes { keySize ->
            generateDigests { digest, digestSize ->
                val keyParameters = KeyParameters(keySize.inBits, digest.name, digestSize)
                val keyParametersId = api.keyPairs.saveParameters(keyParameters)
                algorithm.keyPairGenerator(keySize, digest).generateKeys(keyIterations) { keyPair ->
                    val keyReference = api.keyPairs.saveData(
                        keyParametersId, KeyPairData(
                            public = KeyData {
                                put(StringKeyFormat.DER, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER))
                                if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.JWK))
                        },
                        private = KeyData {
                            put(StringKeyFormat.DER, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.DER))
                            if (provider.supportsJwk) put(StringKeyFormat.JWK, keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.JWK))
                        }
                    ))
                    block(keyPair, keyReference, keyParameters)
                }
            }
        }
    }

    protected suspend fun CompatibilityTestContext<A>.validateKeys() = buildMap {
        api.keyPairs.getParameters<KeyParameters> { (_, digestName), parametersId ->
            val digest = digest(digestName)

            val privateKeyDecoder = algorithm.privateKeyDecoder(digest)
            val publicKeyDecoder = algorithm.publicKeyDecoder(digest)

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference ->
                val publicKeys = publicKeyDecoder.decodeFrom(public.formats) { stringFormat ->
                    when (stringFormat) {
                        StringKeyFormat.DER -> RSA.PublicKey.Format.DER
                        StringKeyFormat.JWK -> RSA.PublicKey.Format.JWK.takeIf { provider.supportsJwk }
                        else                -> error("Unsupported key format: $stringFormat") //TODO
                    }
                }
                publicKeys.forEach { publicKey ->
                    public.formats[StringKeyFormat.DER]?.let { bytes ->
                        assertContentEquals(bytes, publicKey.encodeTo(RSA.PublicKey.Format.DER))
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
                        assertContentEquals(bytes, privateKey.encodeTo(RSA.PrivateKey.Format.DER))
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
