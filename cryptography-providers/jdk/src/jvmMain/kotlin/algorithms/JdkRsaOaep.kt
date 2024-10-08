/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*
import javax.crypto.spec.*

internal class JdkRsaOaep(
    private val state: JdkCryptographyState,
) : RSA.OAEP {

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey> =
        RsaOaepPublicKeyDecoder(state, digest.rsaHashAlgorithmName())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> =
        RsaOaepPrivateKeyDecoder(state, digest.rsaHashAlgorithmName())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.OAEP.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.inBits,
            publicExponent.toJavaBigInteger(),
        )
        return RsaOaepKeyPairGenerator(state, rsaParameters, digest.rsaHashAlgorithmName())
    }
}

private class RsaOaepPublicKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPublicKeyDecoder<RSA.OAEP.PublicKey>(state) {
    override fun JPublicKey.convert(): RSA.OAEP.PublicKey {
        return RsaOaepPublicKey(state, this, hashAlgorithmName)
    }
}

private class RsaOaepPrivateKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPrivateKeyDecoder<RSA.OAEP.PrivateKey>(state) {
    override fun JPrivateKey.convert(): RSA.OAEP.PrivateKey = RsaOaepPrivateKey(state, this, hashAlgorithmName)
}

private class RsaOaepKeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
    private val hashAlgorithmName: String,
) : JdkKeyPairGenerator<RSA.OAEP.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.OAEP.KeyPair = RsaOaepKeyPair(state, this, hashAlgorithmName)
}

private class RsaOaepKeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
    hashAlgorithmName: String,
) : RSA.OAEP.KeyPair {
    override val publicKey: RSA.OAEP.PublicKey = RsaOaepPublicKey(state, keyPair.public, hashAlgorithmName)
    override val privateKey: RSA.OAEP.PrivateKey = RsaOaepPrivateKey(state, keyPair.private, hashAlgorithmName)
}

private class RsaOaepPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    hashAlgorithmName: String,
) : RSA.OAEP.PublicKey, RsaPublicEncodableKey(key) {
    private val encryptor = RsaOaepEncryptor(state, key, hashAlgorithmName)
    override fun encryptor(): AuthenticatedEncryptor = encryptor
}

private class RsaOaepPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    hashAlgorithmName: String,
) : RSA.OAEP.PrivateKey, RsaPrivateEncodableKey(key) {
    private val decryptor = RsaOaepDecryptor(state, key, hashAlgorithmName)
    override fun decryptor(): AuthenticatedDecryptor = decryptor
}

private class RsaOaepEncryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : BaseAuthenticatedEncryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            val parameters = OAEPParameterSpec(
                hashAlgorithmName,
                "MGF1",
                MGF1ParameterSpec(hashAlgorithmName),
                associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
            )
            init(JCipher.ENCRYPT_MODE, key, parameters, state.secureRandom)
        })
    }
}

private class RsaOaepDecryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : BaseAuthenticatedDecryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            val parameters = OAEPParameterSpec(
                hashAlgorithmName,
                "MGF1",
                MGF1ParameterSpec(hashAlgorithmName),
                associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
            )
            init(JCipher.DECRYPT_MODE, key, parameters, state.secureRandom)
        })
    }
}
