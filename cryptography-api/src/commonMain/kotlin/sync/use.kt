/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.sync

import dev.whyoleg.cryptography.api.v2.algorithms.*
import dev.whyoleg.cryptography.api.v2.algorithms.core.*
import kotlinx.io.bytestring.*

private suspend fun test(digest: Digest) {
    digest.hash(
        "".encodeToByteString(),
        Unit
    )

    val hash = digest.createHashFunction(DigestAlgorithm.Sha1).use { function ->
        function.update("".encodeToByteString())
        function.hash()
    }
}

//private fun test(provider: CryptographyProvider) {
//    RsaPublicKeyFactory()
//        .decodeFromPem()
//        .fetch(RsaOaep)
//    Digest(DigestAlgorithm.Sha1)
//    val sha1 = Digest(DigestParameters(DigestAlgorithm.Sha1))
//
//    sha1.hash("".encodeToByteString(), Unit)
//    provider.fetch(Digest, DigestParameters(DigestAlgorithm.Sha1))
//}
