/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import dev.whyoleg.cryptography.api.*

import kotlin.jvm.*

// crypto.algorithms
@JvmInline
public value class EcCurve(public val name: String) {
    public companion object {
        public val P256: EcCurve = EcCurve("P256")
    }
}

// crypto.algorithms
public class EcKeyPairGeneratorParameters(
    public val curve: EcCurve,
)

// crypto.core.algorithms
public interface EcKeyPairGenerator : KeyPairGenerator<EcKeyPairGeneratorParameters, EcPublicKey, EcPrivateKey> {
    public companion object Tag : CryptographyProvider.Tag<EcKeyPairGenerator>
}

// crypto.core.algorithms
public interface EcPublicKeyFactory : PublicKeyFactory<EcPublicKey> {
    public companion object Tag : CryptographyProvider.Tag<EcPublicKeyFactory>
}

// crypto.algorithms
public interface EcPublicKey : PublicKey, CryptographyComponent<EcPublicKey> {

}

// crypto.algorithms
public interface EcPrivateKey : PrivateKey, CryptographyComponent<EcPrivateKey> {

}

// crypto.core.algorithms
public interface EcdsaSigner

// crypto.core.algorithms
public interface EcdsaVerifier
