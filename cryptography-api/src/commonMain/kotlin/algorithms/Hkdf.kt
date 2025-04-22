/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import dev.whyoleg.cryptography.api.*
import kotlinx.io.bytestring.*

// crypto.core.algorithms
public interface Hkdf : SecretDerivationPrimitive<HkdfParameters> {
    public companion object Tag : CryptographyProvider.Tag<Hkdf>
}

// crypto.algorithms
public class HkdfParameters(
    // TODO?
    public val digest: CryptographyProvider.Tag<SimpleDigest>,
    public val outputSize: Int,
    public val salt: ByteString,
    public val info: ByteString? = null,
)

// crypto.async.algorithms
public interface AsyncHkdf : AsyncSecretDerivationPrimitive<HkdfParameters> {
    public companion object Tag : CryptographyProvider.Tag<AsyncHkdf>
}


// HashPrimitive.hash(Sha1, provider, bytes)

// provider.hashPrimitive(Sha1).hash(bytes)
// Sha1.hash(bytes)
