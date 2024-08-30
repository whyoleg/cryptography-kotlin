/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

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

        @OptIn(UnsafeByteStringApi::class)
        override suspend fun generateSharedSecret(other: ECDH.PrivateKey): ByteString {
            check(other is EcdhPrivateKey)
            return UnsafeByteStringOperations.wrapUnsafe(
                WebCrypto.deriveBits(
                    algorithm = EcdhKeyDeriveAlgorithm(publicKey),
                    baseKey = other.privateKey,
                    length = curveOrderSize(publicKey.algorithm.ecKeyAlgorithmNamedCurve).inBits
                )
            )
        }

        override fun generateSharedSecretBlocking(other: ECDH.PrivateKey): ByteString = nonBlocking()
    }

    private class EcdhPrivateKey(
        privateKey: CryptoKey,
    ) : EcPrivateKey(privateKey), ECDH.PrivateKey, SharedSecretGenerator<ECDH.PublicKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PublicKey> = this

        @OptIn(UnsafeByteStringApi::class)
        override suspend fun generateSharedSecret(other: ECDH.PublicKey): ByteString {
            check(other is EcdhPublicKey)
            return UnsafeByteStringOperations.wrapUnsafe(
                WebCrypto.deriveBits(
                    algorithm = EcdhKeyDeriveAlgorithm(other.publicKey),
                    baseKey = privateKey,
                    length = curveOrderSize(privateKey.algorithm.ecKeyAlgorithmNamedCurve).inBits
                )
            )
        }

        override fun generateSharedSecretBlocking(other: ECDH.PublicKey): ByteString = nonBlocking()
    }
}
