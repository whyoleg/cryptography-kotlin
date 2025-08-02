/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

public typealias JwsSigner = (header: JwsHeader, signingInput: ByteArray) -> ByteArray
public typealias JwsVerifier = (header: JwsHeader, signingInput: ByteArray, signature: ByteArray) -> Boolean

// TODO: decide should we support partial signing
@DelicateJoseApi
public inline fun JwsContent.sign(signer: JwsSigner): JwsObject = TODO()

@DelicateJoseApi
public inline fun JwsContent.Compact.sign(signer: JwsSigner): JwsObject.Compact = TODO()

// options: at least once (will return all valid), at most once (will stop after first), all (will return all or not at all)
// TODO: decide what to do on partial verification
@DelicateJoseApi
public inline fun JwsObject.verify(verifier: JwsVerifier): JwsContent = TODO()

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
