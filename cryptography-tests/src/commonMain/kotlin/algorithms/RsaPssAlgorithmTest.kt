/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*

typealias RsaPssSaltTestGroupValidator = TestGroupValidator<RsaPssSaltTestParameters, SignatureTestDataValidator>

@Serializable
data class RsaPssSaltTestParameters(
    // `null` for the default salt size (digest size)
    val saltSizeBytes: Int?,
) : TestParameters {
    override val id: String get() = "salt-${saltSizeBytes ?: "default"}"
}

// RSA-PSS -> [digest, key size] -> [key pair] -> [salt size] -> [signature]
abstract class RsaPssAlgorithmTest(cryptographyProvider: CryptographyProvider) :
    RsaAlgorithmTest<RSA.PSS, RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair, RsaPssSaltTestGroupValidator>(
        provider = cryptographyProvider,
        algorithmId = RSA.PSS,
        algorithmLimitation = {
            when {
                provider.isCryptoKit -> fails("RSA-PSS is not supported")
                provider.isJdkDefault && platform.isAndroid
                    -> fails("RSA-PSS is not supported on Android without BouncyCastle")
                else                 -> null
            }
        },
    ) {
    override fun TestValidatorScope.keyValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.PSS.PublicKey>,
        privateKeys: List<RSA.PSS.PrivateKey>,
    ): RsaPssSaltTestGroupValidator = group<RsaPssSaltTestParameters, _>(
        limitation = { (saltSizeBytes) ->
            when {
                saltSizeBytes != null && provider.isApple
                     -> fails("Custom salt size is not supported")
                // unsupported digests fail when creating decoders and generators (RSA group)
                else -> null
            }
        },
    ) { (saltSizeBytes) ->
        val saltSize = saltSizeBytes?.bytes
        signatures(
            verifiers = publicKeys.map { if (saltSize == null) it.signatureVerifier() else it.signatureVerifier(saltSize) },
            generators = privateKeys.map { if (saltSize == null) it.signatureGenerator() else it.signatureGenerator(saltSize) },
            signatureSizes = listOf(parameters.keySize),
            // without salt the signature is deterministic
            deterministic = saltSizeBytes == 0,
            limitation = { operation ->
                when {
                    // fails only when signing or verifying
                    provider.isWebCrypto && platform.isBrowserSafari && (saltSizeBytes ?: 0) > parameters.digest.digestSize
                         -> fails("Salt size bigger than digest size is not supported")
                    // signers are created, but signing fails with `NullPointerException`, verification works
                    operation is SignatureTestOperation.GenerateSignature &&
                            parameters.digest in sha3Digests && provider.isJdkDefault && platform.isJdk { major < 17 }
                        -> fails("Signing with SHA3 digests is not supported on old JDK")
                    else -> null
                }
            },
        )
    }

    context(context: TestGenerationContext)
    override suspend fun RsaPssSaltTestGroupValidator.generateRandom(parameters: RsaTestParameters, keyPair: RSA.PSS.KeyPair) {
        val digestSize = parameters.digest.digestSize
        val maxSaltSize = (parameters.keySizeBits - 1 + 7) / 8 - digestSize - 2
        listOf(null, 0, digestSize, maxSaltSize).forEach { saltSizeBytes ->
            group(RsaPssSaltTestParameters(saltSizeBytes)) {
                generateSignatures(
                    generator = when (saltSizeBytes) {
                        null -> keyPair.privateKey.signatureGenerator()
                        else -> keyPair.privateKey.signatureGenerator(saltSizeBytes.bytes)
                    },
                    messageSizes = listOf(0, 1, 100, 10000) + List(1) { CryptographyRandom.nextInt(10000) },
                )
            }
        }
    }
}
