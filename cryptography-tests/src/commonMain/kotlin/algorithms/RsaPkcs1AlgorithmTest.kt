/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*

typealias RsaPkcs1ModeTestGroupValidator<V> = TestGroupValidator<RsaPkcs1ModeTestParameters, V>

@Serializable
enum class RsaPkcs1Mode { Signature, Encryption }

@Serializable
data class RsaPkcs1ModeTestParameters(val mode: RsaPkcs1Mode) : TestParameters {
    override val id: String get() = mode.name.lowercase()
}

// RSA-PKCS1 signature: RSA-PKCS1-V1.5-signature -> [digest, key size] -> [key pair] -> [signature mode] -> [signature]
abstract class RsaPkcs1SignatureAlgorithmTest(cryptographyProvider: CryptographyProvider) :
    RsaPkcs1AlgorithmTest<SignatureTestDataValidator>(cryptographyProvider, RsaPkcs1Mode.Signature, singleDigest = false) {

    // all providers fail when creating signers and verifiers
    override fun TestLimitationScope.modeLimitation(parameters: RsaTestParameters): TestLimitation? =
        failsIfSignatureDigestUnsupported(parameters.digest)

    override fun TestValidatorScope.modeValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.PKCS1.PublicKey>,
        privateKeys: List<RSA.PKCS1.PrivateKey>,
    ): SignatureTestDataValidator = signatures(
        verifiers = publicKeys.map { it.signatureVerifier() },
        generators = privateKeys.map { it.signatureGenerator() },
        signatureSizes = listOf(parameters.keySize),
        deterministic = true,
    )

    context(context: TestGenerationContext)
    override suspend fun SignatureTestDataValidator.generateModeRandom(parameters: RsaTestParameters, keyPair: RSA.PKCS1.KeyPair) {
        generateSignatures(
            generator = keyPair.privateKey.signatureGenerator(),
            messageSizes = listOf(0, 1, 100, 10000) + List(1) { CryptographyRandom.nextInt(10000) },
        )
    }
}

// RSA-PKCS1 encryption: RSA-PKCS1-V1.5-encryption -> [digest, key size] -> [key pair] -> [encryption mode] -> [ciphertext]
abstract class RsaPkcs1EncryptionAlgorithmTest(cryptographyProvider: CryptographyProvider) :
// encryption doesn't use the digest
    RsaPkcs1AlgorithmTest<CipherTestDataValidator>(cryptographyProvider, RsaPkcs1Mode.Encryption, singleDigest = true) {

    // all providers fail when creating encryptors and decryptors
    override fun TestLimitationScope.modeLimitation(parameters: RsaTestParameters): TestLimitation? = when {
        provider.isWebCrypto -> fails("RSA-PKCS1 encryption is not supported")
        else                 -> null
    }

    override fun TestValidatorScope.modeValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.PKCS1.PublicKey>,
        privateKeys: List<RSA.PKCS1.PrivateKey>,
    ): CipherTestDataValidator = ciphertexts(
        encryptors = publicKeys.map { it.encryptor() },
        decryptors = privateKeys.map { it.decryptor() },
        ivSize = 0,
        ciphertextSize = { parameters.keySize },
        deterministic = false,
    )

    context(context: TestGenerationContext)
    override suspend fun CipherTestDataValidator.generateModeRandom(parameters: RsaTestParameters, keyPair: RSA.PKCS1.KeyPair) {
        // PKCS1 padding takes 11 bytes
        val maxPlaintextSize = parameters.keySize - 11
        generateCiphertexts(keyPair.publicKey.encryptor(), listOf(1, 100, maxPlaintextSize))
    }
}

// RSA-PKCS1 supports both signatures and encryption, which are tested in separate suites;
// the mode group is the creation of signers or encryptors, so that it could be limited
abstract class RsaPkcs1AlgorithmTest<V : TestInputValidator>(
    cryptographyProvider: CryptographyProvider,
    private val mode: RsaPkcs1Mode,
    singleDigest: Boolean,
) : RsaAlgorithmTest<RSA.PKCS1, RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair, RsaPkcs1ModeTestGroupValidator<V>>(
    provider = cryptographyProvider,
    algorithmId = RSA.PKCS1,
    algorithmLimitation = {
        when {
            provider.isCryptoKit -> fails("RSA-PKCS1 is not supported")
            else                 -> null
        }
    },
    singleDigest = singleDigest,
    suiteId = "${RSA.PKCS1.name}-${mode.name.lowercase()}",
) {
    protected abstract fun TestLimitationScope.modeLimitation(parameters: RsaTestParameters): TestLimitation?

    protected abstract fun TestValidatorScope.modeValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.PKCS1.PublicKey>,
        privateKeys: List<RSA.PKCS1.PrivateKey>,
    ): V

    context(context: TestGenerationContext)
    protected abstract suspend fun V.generateModeRandom(parameters: RsaTestParameters, keyPair: RSA.PKCS1.KeyPair)

    final override fun TestValidatorScope.keyValidator(
        parameters: RsaTestParameters,
        publicKeys: List<RSA.PKCS1.PublicKey>,
        privateKeys: List<RSA.PKCS1.PrivateKey>,
    ): RsaPkcs1ModeTestGroupValidator<V> = group<RsaPkcs1ModeTestParameters, V>(
        limitation = { modeLimitation(parameters) },
    ) { modeValidator(parameters, publicKeys, privateKeys) }

    context(context: TestGenerationContext)
    final override suspend fun RsaPkcs1ModeTestGroupValidator<V>.generateRandom(parameters: RsaTestParameters, keyPair: RSA.PKCS1.KeyPair) {
        group(RsaPkcs1ModeTestParameters(mode)) { generateModeRandom(parameters, keyPair) }
    }
}
