/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.materials

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.unsafe.*

/**
 * Decodes DH parameters from DER-encoded DHParameter ASN.1 structure.
 */
@CryptographyProviderApi
public fun decodeDhParametersFromDer(bytes: ByteArray): Pair<BigInt, BigInt> {
    val params = Der.decodeFromByteArray(DhParameters.serializer(), bytes)
    return params.prime to params.base
}

/**
 * Encodes DH parameters to DER-encoded DHParameter ASN.1 structure.
 */
@CryptographyProviderApi
public fun encodeDhParametersToDer(prime: BigInt, base: BigInt): ByteArray {
    return Der.encodeToByteArray(
        DhParameters.serializer(),
        DhParameters(prime, base, privateValueLength = null)
    )
}

/**
 * Unwraps DH parameters from PEM format.
 */
@OptIn(UnsafeByteStringApi::class)
@CryptographyProviderApi
public fun unwrapDhParametersPem(bytes: ByteArray): ByteArray {
    val document = PemDocument.decode(bytes)
    check(document.label == PemLabel.DhParameters) {
        "Wrong PEM label, expected ${PemLabel.DhParameters}, actual ${document.label}"
    }
    UnsafeByteStringOperations.withByteArrayUnsafe(document.content) { return it }
}

/**
 * Wraps DH parameters in PEM format.
 */
@OptIn(UnsafeByteStringApi::class)
@CryptographyProviderApi
public fun wrapDhParametersPem(derBytes: ByteArray): ByteArray {
    val document = PemDocument(PemLabel.DhParameters, UnsafeByteStringOperations.wrapUnsafe(derBytes))
    return document.encodeToByteArray()
}
