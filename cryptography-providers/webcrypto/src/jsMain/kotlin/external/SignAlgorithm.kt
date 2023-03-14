/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface SignAlgorithm : Algorithm
internal sealed external interface VerifyAlgorithm : Algorithm
internal sealed external interface SignatureAlgorithm : SignAlgorithm, VerifyAlgorithm

internal sealed external interface RsaPssParams : SignatureAlgorithm {
    var saltLength: Int
}

internal fun RsaPssParams(saltLength: Int): RsaPssParams = Algorithm("RSA-PSS") {
    this.saltLength = saltLength
}

internal sealed external interface EcdsaParams : SignatureAlgorithm {
    var hash: String
}

internal fun EcdsaParams(hash: String): EcdsaParams = Algorithm("ECDSA") {
    this.hash = hash
}
