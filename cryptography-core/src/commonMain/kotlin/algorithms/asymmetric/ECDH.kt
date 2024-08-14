/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDH : EC<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDH> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDH>("ECDH")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>
    }
}
