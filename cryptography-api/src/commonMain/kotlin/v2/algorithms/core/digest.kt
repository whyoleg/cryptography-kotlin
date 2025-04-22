/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.v2.algorithms.core

import dev.whyoleg.cryptography.api.v2.*
import dev.whyoleg.cryptography.api.v2.algorithms.*
import dev.whyoleg.cryptography.api.v2.primitives.core.*

public interface Digest : HashPrimitive<Unit> {
    public val outputSize: Int

    public companion object Tag : CryptographyProvider.Tag<Digest, DigestParameters>
}

//public fun HashPrimitive<DigestParameters>.createHashFunction(algorithm: DigestAlgorithm): HashFunction<DigestParameters> {
//    return createHashFunction(DigestParameters(algorithm))
//}
//
//public fun HashFunction<DigestParameters>.reset(algorithm: DigestAlgorithm) {
//    reset(DigestParameters(algorithm))
//}
//
//public fun HashPrimitive<DigestParameters>.hash(data: ByteString, algorithm: DigestAlgorithm): ByteString {
//    return hash(data, DigestParameters(algorithm))
//}
//
//public fun HashPrimitive<DigestParameters>.hash(data: RawSource, algorithm: DigestAlgorithm): ByteString {
//    return hash(data, DigestParameters(algorithm))
//}
