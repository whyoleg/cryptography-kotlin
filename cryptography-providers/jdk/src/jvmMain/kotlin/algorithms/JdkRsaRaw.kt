/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import java.security.interfaces.*
import java.security.spec.*

internal class JdkRsaRaw(
    private val state: JdkCryptographyState,
) : RSA.RAW {

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.RAW.PublicKey> =
        RsaRawPublicKeyDecoder(state)

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.RAW.PrivateKey> =
        RsaRawPrivateKeyDecoder(state)

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.RAW.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.inBits,
            publicExponent.toJavaBigInteger(),
        )
        return RsaRawKeyPairGenerator(state, rsaParameters)
    }
}

private class RsaRawPublicKeyDecoder(
    state: JdkCryptographyState,
) : RsaPublicKeyDecoder<RSA.RAW.PublicKey>(state) {
    override fun JPublicKey.convert(): RSA.RAW.PublicKey = RsaRawPublicKey(state, this)
}

private class RsaRawPrivateKeyDecoder(
    state: JdkCryptographyState,
) : RsaPrivateKeyDecoder<RSA.RAW.PrivateKey>(state) {
    override fun JPrivateKey.convert(): RSA.RAW.PrivateKey = RsaRawPrivateKey(state, this)
}

private class RsaRawKeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
) : JdkKeyPairGenerator<RSA.RAW.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.RAW.KeyPair = RsaRawKeyPair(state, this)
}

private class RsaRawKeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
) : RSA.RAW.KeyPair {
    override val publicKey: RSA.RAW.PublicKey = RsaRawPublicKey(state, keyPair.public)
    override val privateKey: RSA.RAW.PrivateKey = RsaRawPrivateKey(state, keyPair.private)
}

private class RsaRawPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : RSA.RAW.PublicKey, RsaPublicEncodableKey(key) {
    override fun encryptor(): Encryptor = RsaRawEncryptor(state, key)
}

private class RsaRawPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : RSA.RAW.PrivateKey, RsaPrivateEncodableKey(key) {
    override fun decryptor(): Decryptor = RsaRawDecryptor(state, key)
}

private class RsaRawEncryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : Encryptor {
    private val cipher = state.cipher("RSA/ECB/NoPadding")

    override fun encryptBlocking(plaintext: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.ENCRYPT_MODE, key, state.secureRandom)
        cipher.doFinal(plaintext)
    }
}

private class RsaRawDecryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : Decryptor {
    private val cipher = state.cipher("RSA/ECB/NoPadding")
    private val outputSize = (key as RSAKey).modulus.bitLength().bits.inBytes

    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, state.secureRandom)
        // for some reason BC provider output size is truncated, so we need to `pad`
        cipher.doFinal(ciphertext).pad(outputSize)
    }
}

private fun ByteArray.pad(size: Int): ByteArray {
    if (this.size == size) return this

    return ByteArray(size).also {
        copyInto(it, size - this.size)
    }
}
