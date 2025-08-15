/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

// null, if not supported, affects JwsSigningMode
public typealias JwsSigner = (headers: JwsHeaders, signingInput: ByteArray) -> ByteArray?
public typealias JwsVerifier = (headers: JwsHeaders, signingInput: ByteArray, signature: ByteArray) -> Boolean

public enum class JwsSigningMode {
    // requires to sign and verify all signatures - fail otherwise
    ALL,

    // requires to sign at least one signature, will try to sign/verify all signatures - fail otherwise
    AT_LEAST_ONCE,

    // requires to verify at most one signature, stop after at least one signature is signed/verified - fail otherwise
    AT_MOST_ONCE,
}

@DelicateJoseApi
public inline fun JwsContent.sign(
    mode: JwsSigningMode,
    signer: JwsSigner,
): JwsObject = TODO()

@DelicateJoseApi
public inline fun JwsContent.Compact.sign(signer: JwsSigner): JwsObject.Compact = TODO()

@DelicateJoseApi
public inline fun JwsObject.verify(
    mode: JwsSigningMode,
    verifier: JwsVerifier,
): JwsContent = TODO()

@DelicateJoseApi
public inline fun JwsObject.Compact.verify(verifier: JwsVerifier): JwsContent.Compact = TODO()

//@PublishedApi
//internal fun signingInput(
//    headerBytes: ByteArray,
//): ByteArray = buildString {
//    Base64Url.encodeToAppendable(header.protected.toJsonString().encodeToByteArray(), this)
//    append('.')
//    Base64Url.encodeToAppendable(payload, this)
//}.encodeToByteArray()
//
//private fun JwsObject.Payload.compactRepresentation(): String = buildString {
//    Base64Url.encodeToAppendable(header.protected.toJsonString().encodeToByteArray(), this)
//    append('.')
//    Base64Url.encodeToAppendable(payload, this)
//    append('.')
//    Base64Url.encodeToAppendable(signature, this)
//}
