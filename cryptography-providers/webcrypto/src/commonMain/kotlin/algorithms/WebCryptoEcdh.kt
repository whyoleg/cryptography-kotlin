/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal object WebCryptoEcdh : WebCryptoEc<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair>(
    algorithmName = "ECDH",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf(), ::EcdhPublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("deriveBits"), ::EcdhPrivateKey),
    keyPairWrapper = ::EcdhKeyPair
), ECDH {
    private class EcdhKeyPair(
        override val publicKey: ECDH.PublicKey,
        override val privateKey: ECDH.PrivateKey,
    ) : ECDH.KeyPair

    private class EcdhPublicKey(
        publicKey: CryptoKey,
    ) : EcPublicKey(publicKey), ECDH.PublicKey, SharedSecretGenerator<ECDH.PrivateKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PrivateKey> = this

        override suspend fun generateSharedSecretToByteArray(other: ECDH.PrivateKey): ByteArray {
            check(other is EcdhPrivateKey)
            return WebCrypto.deriveBits(
                algorithm = KeyDeriveAlgorithm("ECDH", publicKey),
                baseKey = other.privateKey,
                length = curveOrderSize(publicKey.algorithm.ecKeyAlgorithmNamedCurve).inBits
            )
        }

        override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PrivateKey): ByteArray = nonBlocking()
    }

    private class EcdhPrivateKey(
        privateKey: CryptoKey,
    ) : EcPrivateKey(privateKey), ECDH.PrivateKey, SharedSecretGenerator<ECDH.PublicKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PublicKey> = this

        override suspend fun generateSharedSecretToByteArray(other: ECDH.PublicKey): ByteArray {
            check(other is EcdhPublicKey)
            return WebCrypto.deriveBits(
                algorithm = KeyDeriveAlgorithm("ECDH", other.publicKey),
                baseKey = privateKey,
                length = curveOrderSize(privateKey.algorithm.ecKeyAlgorithmNamedCurve).inBits
            )
        }

        override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PublicKey): ByteArray = nonBlocking()
    }
}
