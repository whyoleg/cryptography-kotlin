package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.asymmetric.RSA.OAEP.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal object RsaOaepKeyGeneratorProvider : KeyGeneratorProvider<RSA.KeyPairGeneratorParameters, KeyPair>() {
    override fun provideOperation(parameters: RSA.KeyPairGeneratorParameters): KeyGenerator<KeyPair> = RsaOaepKeyGenerator(
        keySizeBits = parameters.keySize.bits,
        publicExponent = when (val exponent = parameters.publicExponent) {
            RSA.PublicExponent.F4        -> byteArrayOf(0x01, 0x00, 0x01)
            is RSA.PublicExponent.Bytes  -> exponent.value
            is RSA.PublicExponent.Number -> TODO("not yet supported")
            is RSA.PublicExponent.Text   -> TODO("not yet supported")
        },
        hashAlgorithm = parameters.digest.hashAlgorithmName(),
    )
}

internal class RsaOaepKeyGenerator(
    keySizeBits: Int,
    publicExponent: ByteArray,
    hashAlgorithm: String,
) : WebCryptoAsymmetricKeyGenerator<KeyPair>(
    RsaHashedKeyGenerationAlgorithm("RSA-OAEP", keySizeBits, publicExponent, hashAlgorithm),
    arrayOf("encrypt", "decrypt")
) {
    override fun wrap(keyPair: CryptoKeyPair): KeyPair {
        return KeyPair(
            PublicKey(
                NotSupportedProvider(),
                RsaOaepEncryptor(keyPair.publicKey),
            ),
            PrivateKey(
                NotSupportedProvider(),
                RsaOaepDecryptor(keyPair.privateKey)
            )
        )
    }
}

private class RsaOaepEncryptor(
    private val key: CryptoKey,
) : AeadEncryptor, AeadEncryptorProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): AeadEncryptor = this

    override fun ciphertextSize(plaintextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        return WebCrypto.subtle.encrypt(
            algorithm = RsaOaepParams(associatedData),
            key = key,
            data = plaintextInput
        ).await().toByteArray()
    }

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        return encrypt(associatedData, plaintextInput).copyInto(ciphertextOutput)
    }

    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer): Buffer = nonBlocking()
    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = nonBlocking()
    override fun encryptFunction(): AeadEncryptFunction = noFunction()
}

private class RsaOaepDecryptor(
    private val key: CryptoKey,
) : AeadDecryptor, AeadDecryptorProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): AeadDecryptor = this
    override fun plaintextSize(ciphertextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer {
        return WebCrypto.subtle.decrypt(
            algorithm = RsaOaepParams(associatedData),
            key = key,
            data = ciphertextInput
        ).await().toByteArray()
    }

    override suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        return decrypt(associatedData, ciphertextInput).copyInto(plaintextOutput)
    }

    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer): Buffer = nonBlocking()
    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = nonBlocking()
    override fun decryptFunction(): AeadDecryptFunction = noFunction()
}
