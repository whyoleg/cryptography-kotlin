/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

/**
 * Elliptic Curve Diffie-Hellman (ECDH) key agreement
 * as defined in [NIST SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final).
 *
 * ECDH allows two parties to establish a shared secret over an insecure channel
 * using elliptic curve keys. Each party generates a key pair on the same [EC.Curve],
 * then computes the shared secret using their own private key and the other party's public key.
 *
 * ```
 * val aliceKeys = provider.get(ECDH).keyPairGenerator(EC.Curve.P256).generateKey()
 * val bobKeys = provider.get(ECDH).keyPairGenerator(EC.Curve.P256).generateKey()
 * val sharedSecret = aliceKeys.privateKey.sharedSecretGenerator().generateSharedSecret(bobKeys.publicKey)
 * ```
 *
 * The raw shared secret output should not be used directly as a key.
 * Use a key derivation function like [HKDF] to derive actual keys from the shared secret.
 *
 * For key agreement using Montgomery curves, see [XDH].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDH : EC<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDH> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDH>("ECDH")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    /**
     * An ECDH public key that provides shared secret computation via [sharedSecretGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        /**
         * Returns a [SharedSecretGenerator] that computes a shared secret
         * using this public key and a [PrivateKey].
         */
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>
    }

    /**
     * An ECDH private key that provides shared secret computation via [sharedSecretGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey<PublicKey> {
        /**
         * Returns a [SharedSecretGenerator] that computes a shared secret
         * given the other party's [PublicKey].
         */
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>
    }
}
