/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Ecdh : Openssl3Ec<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair>(
    wrapPublicKey = ::EcdhPublicKey,
    wrapPrivateKey = ::EcdhPrivateKey,
    wrapKeyPair = ::EcdhKeyPair,
), ECDH {
    private class EcdhKeyPair(
        override val publicKey: ECDH.PublicKey,
        override val privateKey: ECDH.PrivateKey,
    ) : ECDH.KeyPair

    private class EcdhPrivateKey(
        curve: EC.Curve,
        key: CPointer<EVP_PKEY>,
        publicKey: ECDH.PublicKey?,
    ) : Openssl3EcPrivateKey(curve, key, publicKey), ECDH.PrivateKey, SharedSecretGenerator<ECDH.PublicKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PublicKey): ByteArray {
            check(other is EcdhPublicKey)

            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }

    private class EcdhPublicKey(
        curve: EC.Curve,
        key: CPointer<EVP_PKEY>,
    ) : Openssl3EcPublicKey(curve, key), ECDH.PublicKey, SharedSecretGenerator<ECDH.PrivateKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<ECDH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: ECDH.PrivateKey): ByteArray {
            check(other is EcdhPrivateKey)

            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }
}
