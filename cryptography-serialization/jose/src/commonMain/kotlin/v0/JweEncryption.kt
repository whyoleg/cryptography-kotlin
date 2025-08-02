/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// content encryption - done once
// key encryption - done per recipient

public class JweCiphertext(
    public val iv: ByteArray,
    public val ciphertext: ByteArray,
    public val authenticationTag: ByteArray,
)

// output: iv, ciphertext, authentication tag, encryption key
public typealias JweKeyEncryptor = (header: JweHeader, key: ByteArray) -> ByteArray
public typealias JweKeyDecryptor = (header: JweHeader, encryptedKey: ByteArray) -> ByteArray

// a shared header only
public typealias JweContentEncryptor = (
    header: JweHeader,
    key: ByteArray,
    plaintext: ByteArray,
    authenticatedData: ByteArray,
) -> JweCiphertext // iv, ciphertext, auth tag

public typealias JweContentDecryptor = (
    header: JweHeader,
    key: ByteArray,
    ciphertext: JweCiphertext,
    authenticatedData: ByteArray,
) -> ByteArray

// TODO: decide should we support partial encryption
@DelicateJoseApi
public inline fun JweContent.encrypt(
    keyEncryptor: JweKeyEncryptor,
    contentEncryptor: JweContentEncryptor,
): JweObject = TODO()

@DelicateJoseApi
public inline fun JweContent.Compact.encrypt(
    keyEncryptor: JweKeyEncryptor,
    contentEncryptor: JweContentEncryptor,
): JweObject.Compact = TODO()

// TODO: decide what to do on partial decryption
@DelicateJoseApi
public inline fun JweObject.decrypt(
    keyDecryptor: JweKeyDecryptor,
    contentDecryptor: JweContentDecryptor,
): JweContent = TODO()

@DelicateJoseApi
public inline fun JweObject.Compact.decrypt(
    keyDecryptor: JweKeyDecryptor,
    contentDecryptor: JweContentDecryptor,
): JweContent.Compact = TODO()
