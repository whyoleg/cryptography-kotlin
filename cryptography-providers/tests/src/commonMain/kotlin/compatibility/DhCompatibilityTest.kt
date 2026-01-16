/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

// RFC 3526 MODP Group 14 (2048-bit) DH parameters encoded in DER format.
// This avoids the extremely slow DH parameter generation during tests.
@OptIn(ExperimentalStdlibApi::class)
private val rfc3526Group14Der = (
        "308201080282010100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e08" +
                "8a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f143" +
                "74fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b" +
                "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
                "39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c" +
                "354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec0" +
                "7a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015" +
                "728e5a8aacaa68ffffffffffffffff020102"
        ).hexToByteArray()

private val publicKeyFormats = listOf(
    DH.PublicKey.Format.DER,
    DH.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    DH.PrivateKey.Format.DER,
    DH.PrivateKey.Format.PEM,
).associateBy { it.name }

abstract class DhCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<DH>(DH, provider) {

    @Serializable
    private data class DhKeyParameters(
        val parametersDer: SerializableByteString,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<DH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)

        // Use predefined RFC 3526 parameters (DH parameter generation is extremely slow)
        val parameters = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, rfc3526Group14Der)
        val parametersDer = ByteString(parameters.encodeToByteArray(DH.Parameters.Format.DER))
        val keyParameters = DhKeyParameters(parametersDer)
        val keyParametersId = api.keyPairs.saveParameters(keyParameters)

        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        repeat(keyIterations) {
            val keyPair = parameters.keyPairGenerator().generateKey()

            val publicKeyData = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat))
            val privateKeyData = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))

            val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(publicKeyData, privateKeyData))

            repeat(keyIterations) {
                val otherKeyPair = parameters.keyPairGenerator().generateKey()

                val otherPublicKeyData = KeyData(otherKeyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat))
                val otherPrivateKeyData = KeyData(otherKeyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))

                val otherKeyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(otherPublicKeyData, otherPrivateKeyData))

                // Generate shared secrets in all 4 combinations
                val secrets = listOf(
                    keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.publicKey),
                    keyPair.publicKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.privateKey),
                    otherKeyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey),
                    otherKeyPair.publicKey.sharedSecretGenerator().generateSharedSecret(keyPair.privateKey),
                )

                // Verify all 4 secrets are equal
                repeat(secrets.size) { i ->
                    repeat(secrets.size) { j ->
                        if (j > i) assertContentEquals(secrets[i], secrets[j], "Initial $i + $j")
                    }
                }

                api.sharedSecrets.saveData(
                    parametersId = parametersId,
                    data = SharedSecretData(
                        keyReference = keyReference,
                        otherKeyReference = otherKeyReference,
                        sharedSecret = secrets.first()
                    )
                )
            }
        }
    }

    override suspend fun CompatibilityTestScope<DH>.validate() {
        val keyPairs = validateKeys()

        api.sharedSecrets.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.sharedSecrets.getData<SharedSecretData>(parametersId) { (keyReference, otherKeyReference, sharedSecret), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val (otherPublicKeys, otherPrivateKeys) = keyPairs[otherKeyReference] ?: return@getData

                publicKeys.forEach { publicKey ->
                    otherPrivateKeys.forEach { otherPrivateKey ->
                        assertContentEquals(
                            sharedSecret,
                            publicKey.sharedSecretGenerator().generateSharedSecret(otherPrivateKey),
                            "Public + Other Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            otherPrivateKey.sharedSecretGenerator().generateSharedSecret(publicKey),
                            "Other Private + Public"
                        )
                    }
                }
                privateKeys.forEach { privateKey ->
                    otherPublicKeys.forEach { otherPublicKey ->
                        assertContentEquals(
                            sharedSecret,
                            otherPublicKey.sharedSecretGenerator().generateSharedSecret(privateKey),
                            "Other Public + Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            privateKey.sharedSecretGenerator().generateSharedSecret(otherPublicKey),
                            "Private + Other Public"
                        )
                    }
                }
            }
        }
    }

    private suspend fun CompatibilityTestScope<DH>.validateKeys() = buildMap {
        api.keyPairs.getParameters<DhKeyParameters> { keyParameters, parametersId, _ ->
            val privateKeyDecoder = algorithm.privateKeyDecoder()
            val publicKeyDecoder = algorithm.publicKeyDecoder()

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                val publicKeys = publicKeyDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = publicKeyFormats::getValue,
                    supports = ::supportsKeyFormat,
                ) { _, _, _ -> } // no additional validation needed
                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = privateKeyFormats::getValue,
                    supports = ::supportsKeyFormat,
                ) { _, _, _ -> } // no additional validation needed
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
