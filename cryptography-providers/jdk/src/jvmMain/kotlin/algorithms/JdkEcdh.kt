/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

internal class JdkEcdh(state: JdkCryptographyState) : JdkEc<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair>(state), ECDH {
    override val wrapPublicKey: (JPublicKey, EC.Curve) -> ECDH.PublicKey = ::EcdhPublicKey
    override val wrapPrivateKey: (JPrivateKey, EC.Curve, ECDH.PublicKey?) -> ECDH.PrivateKey = ::EcdhPrivateKey
    override val wrapKeyPair: (ECDH.PublicKey, ECDH.PrivateKey) -> ECDH.KeyPair = ::EcdhKeyPair

    private class EcdhKeyPair(
        override val publicKey: ECDH.PublicKey,
        override val privateKey: ECDH.PrivateKey,
    ) : ECDH.KeyPair

    private inner class EcdhPublicKey(
        key: JPublicKey,
        curve: EC.Curve,
    ) : ECDH.PublicKey, BaseEcPublicKey(key, curve), SharedSecretGenerator<ECDH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("ECDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PrivateKey): ByteArray {
            check(other is EcdhPrivateKey) { "Only key produced by JDK provider is supported" }

            return keyAgreement.doAgreement(state, other.key, key)
        }
    }

    private inner class EcdhPrivateKey(
        key: JPrivateKey,
        curve: EC.Curve,
        publicKey: ECDH.PublicKey?,
    ) : ECDH.PrivateKey, BaseEcPrivateKey(key, curve, publicKey), SharedSecretGenerator<ECDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("ECDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PublicKey): ByteArray {
            check(other is EcdhPublicKey) { "Only key produced by JDK provider is supported" }

            return keyAgreement.doAgreement(state, key, other.key)
        }
    }
}
