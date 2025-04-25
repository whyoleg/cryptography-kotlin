/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.core

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.primitives.*
import dev.whyoleg.cryptography.primitives.core.*
import kotlinx.io.bytestring.*

public interface EcPublicKeyFactory : PublicKeyFactory<EcPublicKey> {
    // TODO?
    public fun decodeCompressedPoint(bytes: ByteString): EcPublicKey
    public fun decodeUncompressedPoint(bytes: ByteString): EcPublicKey

    public companion object Tag : CryptographyProvider.Tag<EcPublicKeyFactory, Unit>
}

public interface EcPrivateKeyFactory : PrivateKeyFactory<EcPrivateKey> {
    public fun decodeSecret(bytes: ByteString): EcPrivateKey

    public companion object Tag : CryptographyProvider.Tag<EcPrivateKeyFactory, Unit>
}

public interface EcKeyPairFactory {
    public fun generate(curve: EcCurve): KeyPair<EcPublicKey, EcPrivateKey>

    public companion object Tag : CryptographyProvider.Tag<EcKeyPairFactory, Unit>
}

public interface EcdsaSigner : SignPrimitive<Unit> {
    public companion object Tag : EcPrivateKey.Tag<EcdsaSigner, EcdsaParameters>
}

public interface EcdsaVerifier : VerifyPrimitive<Unit> {
    public companion object Tag : EcPublicKey.Tag<EcdsaVerifier, EcdsaParameters>
}

// will try to decode any public key supported by the provider
public interface GenericPublicKeyFactory : PublicKeyFactory<PublicKey> {
    public companion object Tag : CryptographyProvider.Tag<GenericPublicKeyFactory, Unit>
}
