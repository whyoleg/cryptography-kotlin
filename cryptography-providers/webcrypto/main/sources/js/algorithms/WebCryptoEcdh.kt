package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.derive.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*

internal object WebCryptoEcdh : ECDH, WebCryptoEc<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair>("ECDH") {
    override val publicKeyUsages: Array<String> get() = arrayOf("deriveBits")
    override val privateKeyUsages: Array<String> get() = arrayOf("deriveBits")
    override val keyPairUsages: Array<String> get() = arrayOf("deriveBits")

    override val publicKeyWrapper: (CryptoKey) -> ECDH.PublicKey = { key ->
        object : ECDH.PublicKey, EncodableKey<EC.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun derivative(): SharedSecretDerivative<EC.PrivateKey.Format> = EcdhDerivative(key, privateKeyFormat, true)
        }
    }
    override val privateKeyWrapper: (CryptoKey) -> ECDH.PrivateKey = { key ->
        object : ECDH.PrivateKey, EncodableKey<EC.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun derivative(): SharedSecretDerivative<EC.PublicKey.Format> = EcdhDerivative(key, publicKeyFormat, false)
        }
    }
    override val keyPairWrapper: (CryptoKeyPair) -> ECDH.KeyPair = { keyPair ->
        object : ECDH.KeyPair {
            override val publicKey: ECDH.PublicKey = publicKeyWrapper(keyPair.publicKey)
            override val privateKey: ECDH.PrivateKey = privateKeyWrapper(keyPair.privateKey)
        }
    }
}

private class EcdhDerivative<KF : KeyFormat>(
    private val thisKey: CryptoKey,
    private val otherKeyFormat: (KF) -> String,
    private val otherKeyIsPrivate: Boolean,
) : SharedSecretDerivative<KF> {
    override suspend fun deriveSharedSecretFrom(keyFormat: KF, keyInput: Buffer): Buffer {
        val otherKey = WebCrypto.subtle.importKeyBinary(
            format = otherKeyFormat(keyFormat),
            keyData = keyInput,
            algorithm = thisKey.algorithm.unsafeCast<KeyImportAlgorithm>(),
            extractable = false,
            keyUsages = arrayOf("deriveBits")
        ).await()

        val length = 256 //TODO

        return when {
            otherKeyIsPrivate -> WebCrypto.subtle.deriveBits(EcdhDerivationAlgorithm(public = thisKey), otherKey, length)
            else              -> WebCrypto.subtle.deriveBits(EcdhDerivationAlgorithm(public = otherKey), thisKey, length)
        }.await().toByteArray()
    }

    override fun deriveSharedSecretFromBlocking(keyFormat: KF, keyInput: Buffer): Buffer = nonBlocking()
}
