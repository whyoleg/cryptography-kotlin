/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

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
    ) : ECDH.PublicKey, BaseEcPublicKey(key), SharedSecretDerivation<ECDH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("ECDH")
        override fun sharedSecretDerivation(): SharedSecretDerivation<ECDH.PrivateKey> = this
        override suspend fun deriveSharedSecret(other: ECDH.PrivateKey): ByteArray = deriveSharedSecretBlocking(other)

        override fun deriveSharedSecretBlocking(other: ECDH.PrivateKey): ByteArray {
            check(other is EcdhPrivateKey) { "Only key produced by JDK provider is supported" }

            return keyAgreement.doAgreement(state, other.key, key)
        }
    }

    private class EcdhPrivateKey(
        private val state: JdkCryptographyState,
        val key: JPrivateKey,
    ) : ECDH.PrivateKey, BaseEcPrivateKey(key), SharedSecretDerivation<ECDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("ECDH")
        override fun sharedSecretDerivation(): SharedSecretDerivation<ECDH.PublicKey> = this
        override suspend fun deriveSharedSecret(other: ECDH.PublicKey): ByteArray = deriveSharedSecretBlocking(other)

        override fun deriveSharedSecretBlocking(other: ECDH.PublicKey): ByteArray {
            check(other is EcdhPublicKey) { "Only key produced by JDK provider is supported" }

            return keyAgreement.doAgreement(state, key, other.key)
        }
    }
}
