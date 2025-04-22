/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import kotlin.jvm.*

@JvmInline
public value class EcCurve(public val name: String) {
    public companion object {
        public val P256: EcCurve = EcCurve("P256")
    }
}

public class EcKeyPairGeneratorParameters(
    public val curve: EcCurve,
)

public interface EcKeyPairGenerator :
    dev.whyoleg.cryptography.api.KeyPairGenerator<EcKeyPairGeneratorParameters, EcPublicKey, EcPrivateKey> {
    public companion object Tag : dev.whyoleg.cryptography.api.CryptographyProvider.Tag<EcKeyPairGenerator>
}

public interface EcPublicKeyFactory : dev.whyoleg.cryptography.api.PublicKeyFactory<EcPublicKey> {
    public companion object Tag : dev.whyoleg.cryptography.api.CryptographyProvider.Tag<EcPublicKeyFactory>
}

public interface EcPublicKey : dev.whyoleg.cryptography.api.PublicKey, dev.whyoleg.cryptography.api.CryptographyComponent<EcPublicKey> {

}

public interface EcPrivateKey : dev.whyoleg.cryptography.api.PrivateKey, dev.whyoleg.cryptography.api.CryptographyComponent<EcPrivateKey> {

}

public interface EcdsaSigner
public interface EcdsaVerifier
