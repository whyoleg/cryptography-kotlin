/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.interfaces.*

internal class JdkRsaRaw(
    state: JdkCryptographyState,
) : JdkRsa<RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair>(state), RSA.RAW {
    override val wrapPublicKey: (JPublicKey, String) -> RSA.RAW.PublicKey = ::RsaRawPublicKey
    override val wrapPrivateKey: (JPrivateKey, String, RSA.RAW.PublicKey?) -> RSA.RAW.PrivateKey = ::RsaRawPrivateKey
    override val wrapKeyPair: (RSA.RAW.PublicKey, RSA.RAW.PrivateKey) -> RSA.RAW.KeyPair = ::RsaRawKeyPair

    private class RsaRawKeyPair(
        override val publicKey: RSA.RAW.PublicKey,
        override val privateKey: RSA.RAW.PrivateKey,
    ) : RSA.RAW.KeyPair

    private inner class RsaRawPublicKey(
        key: JPublicKey,
        @Suppress("unused") hashAlgorithmName: String,
    ) : RSA.RAW.PublicKey, RsaPublicEncodableKey(key) {
        override fun encryptor(): Encryptor = RsaRawEncryptor(state, key)
    }

    private inner class RsaRawPrivateKey(
        key: JPrivateKey,
        hashAlgorithmName: String,
        publicKey: RSA.RAW.PublicKey?,
    ) : RSA.RAW.PrivateKey, RsaPrivateEncodableKey(key, hashAlgorithmName, publicKey) {
        override fun decryptor(): Decryptor = RsaRawDecryptor(state, key)
    }
}

private class RsaRawEncryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : BaseEncryptor {
    private val cipher = state.cipher("RSA/ECB/NoPadding")

    override fun createEncryptFunction(): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, state.secureRandom)
        })
    }
}

private class RsaRawDecryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : BaseDecryptor {
    private val cipher = state.cipher("RSA/ECB/NoPadding")
    private val outputSize = (key as RSAKey).modulus.bitLength().bits.inBytes

    override fun createDecryptFunction(): CipherFunction {
        return RsaRawDecryptFunction(outputSize, cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, state.secureRandom)
        })
    }

    // TODO: add some tests for this
    // for some reason, BC provider output size is truncated, so we need to ensure it's padded
    private class RsaRawDecryptFunction(
        private val outputSize: Int,
        cipher: Pooled.Resource<JCipher>,
    ) : JdkCipherFunction(cipher) {
        override fun maxOutputSize(inputSize: Int): Int {
            return outputSize
        }

        override fun finalizeToByteArray(): ByteArray {
            return super.finalizeToByteArray().pad(outputSize)
        }

        override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            super.finalizeIntoByteArray(destination, destinationOffset)
            return outputSize
        }

        override fun transformAndFinalizeToByteArray(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
            return super.transformAndFinalizeToByteArray(source, startIndex, endIndex).pad(outputSize)
        }

        override fun transformAndFinalizeIntoByteArray(
            source: ByteArray,
            destination: ByteArray,
            destinationOffset: Int,
            startIndex: Int,
            endIndex: Int,
        ): Int {
            super.transformAndFinalizeIntoByteArray(source, destination, destinationOffset, startIndex, endIndex)
            return outputSize
        }

        private fun ByteArray.pad(size: Int): ByteArray {
            if (this.size == size) return this

            return ByteArray(size).also {
                copyInto(it, size - this.size)
            }
        }
    }
}
