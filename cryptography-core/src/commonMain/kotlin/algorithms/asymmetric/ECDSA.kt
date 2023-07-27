/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.signature.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDSA : EC<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDSA>("ECDSA")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        public fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat = SignatureFormat.RAW,
        ): SignatureVerifier
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        public fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat = SignatureFormat.RAW,
        ): SignatureGenerator
    }

    public enum class SignatureFormat {
        //IEEE P1363 format
        RAW,

        //X.509 format
        DER
    }
}
