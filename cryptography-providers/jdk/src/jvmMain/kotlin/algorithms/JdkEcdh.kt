/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal class JdkEcdh(state: JdkCryptographyState) : JdkEc<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair>(state), ECDH {
    override fun JPublicKey.convert(): ECDH.PublicKey = EcdhPublicKey(state, this)
    override fun JPrivateKey.convert(): ECDH.PrivateKey = EcdhPrivateKey(state, this)
    override fun JKeyPair.convert(): ECDH.KeyPair = EcdhKeyPair(public.convert(), private.convert())

    private class EcdhKeyPair(
        override val publicKey: ECDH.PublicKey,
        override val privateKey: ECDH.PrivateKey,
    ) : ECDH.KeyPair

    private class EcdhPublicKey(
        private val state: JdkCryptographyState,
        val key: JPublicKey,
    ) : ECDH.PublicKey, BaseEcPublicKey(key) {
        override fun sharedSecretDerivation(): SharedSecretDerivation<ECDH.PrivateKey> = EcdhPublicKeySecretDerivation(state, key)
    }

    private class EcdhPrivateKey(
        private val state: JdkCryptographyState,
        val key: JPrivateKey,
    ) : ECDH.PrivateKey, BaseEcPrivateKey(key) {
        override fun sharedSecretDerivation(): SharedSecretDerivation<ECDH.PublicKey> = EcdhPrivateKeySecretDerivation(state, key)
    }

    private class EcdhPublicKeySecretDerivation(
        private val state: JdkCryptographyState,
        private val publicKey: JPublicKey,
    ) : SharedSecretDerivation<ECDH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("ECDH")

        override fun deriveSharedSecretBlocking(other: ECDH.PrivateKey): ByteArray {
            check(other is EcdhPrivateKey) { "Only ${EcdhPrivateKey::class} supported" }

            return keyAgreement.use {
                it.init(other.key, state.secureRandom)
                it.doPhase(publicKey, true)
                it.generateSecret()
            }
        }

        override suspend fun deriveSharedSecret(other: ECDH.PrivateKey): ByteArray = deriveSharedSecretBlocking(other)
    }

    private class EcdhPrivateKeySecretDerivation(
        private val state: JdkCryptographyState,
        private val privateKey: JPrivateKey,
    ) : SharedSecretDerivation<ECDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("ECDH")

        override fun deriveSharedSecretBlocking(other: ECDH.PublicKey): ByteArray {
            check(other is EcdhPublicKey) { "Only ${EcdhPublicKey::class} supported" }

            return keyAgreement.use {
                it.init(privateKey, state.secureRandom)
                it.doPhase(other.key, true)
                it.generateSecret()
            }
        }

        override suspend fun deriveSharedSecret(other: ECDH.PublicKey): ByteArray = deriveSharedSecretBlocking(other)
    }
}
