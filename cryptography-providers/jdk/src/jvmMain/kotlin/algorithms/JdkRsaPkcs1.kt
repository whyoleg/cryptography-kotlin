/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.binary.BinarySize
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*

internal class JdkRsaPkcs1(
    private val state: JdkCryptographyState,
) : RSA.PKCS1 {

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PKCS1.PublicKey> =
        RsaPkcs1PublicKeyDecoder(state, digest.hashAlgorithmName())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PKCS1.PrivateKey> =
        RsaPkcs1PrivateKeyDecoder(state, digest.hashAlgorithmName())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.PKCS1.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.inBits,
            publicExponent.toJavaBigInteger(),
        )
        return RsaPkcs1KeyPairGenerator(state, rsaParameters, digest.hashAlgorithmName())
    }
}

private class RsaPkcs1PublicKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPublicKeyDecoder<RSA.PKCS1.PublicKey>(state) {
    override fun JPublicKey.convert(): RSA.PKCS1.PublicKey = RsaPkcs1PublicKey(state, this, hashAlgorithmName)
}

private class RsaPkcs1PrivateKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPrivateKeyDecoder<RSA.PKCS1.PrivateKey>(state) {
    override fun JPrivateKey.convert(): RSA.PKCS1.PrivateKey = RsaPkcs1PrivateKey(state, this, hashAlgorithmName)
}


private class RsaPkcs1KeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
    private val hashAlgorithmName: String,
) : JdkKeyPairGenerator<RSA.PKCS1.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.PKCS1.KeyPair = RsaPkcs1KeyPair(state, this, hashAlgorithmName)
}

private class RsaPkcs1KeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
    hashAlgorithmName: String,
) : RSA.PKCS1.KeyPair {
    override val publicKey: RSA.PKCS1.PublicKey = RsaPkcs1PublicKey(state, keyPair.public, hashAlgorithmName)
    override val privateKey: RSA.PKCS1.PrivateKey = RsaPkcs1PrivateKey(state, keyPair.private, hashAlgorithmName)
}

private class RsaPkcs1PublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : RSA.PKCS1.PublicKey, RsaPublicEncodableKey(key) {
    override fun signatureVerifier(): SignatureVerifier {
        return JdkSignatureVerifier(state, key, hashAlgorithmName + "withRSA", null)
    }

    override fun encryptor(): Encryptor = RsaPkcs1Encryptor(state, key)
}

private class RsaPkcs1PrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : RSA.PKCS1.PrivateKey, RsaPrivateEncodableKey(key) {
    override fun signatureGenerator(): SignatureGenerator {
        return JdkSignatureGenerator(state, key, hashAlgorithmName + "withRSA", null)
    }

    override fun decryptor(): Decryptor = RsaPkcs1Decryptor(state, key)
}

private class RsaPkcs1Encryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : Encryptor {
    private val cipher = state.cipher("RSA/ECB/PKCS1Padding")

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.ENCRYPT_MODE, key, state.secureRandom)
        cipher.doFinal(plaintextInput)
    }
}

private class RsaPkcs1Decryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : Decryptor {
    private val cipher = state.cipher("RSA/ECB/PKCS1Padding")

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, state.secureRandom)
        cipher.doFinal(ciphertextInput)
    }
}