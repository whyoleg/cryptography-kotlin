/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

// content encryption - done once
// key encryption - done per recipient

public class JweCiphertext(
    public val iv: ByteArray,
    public val ciphertext: ByteArray,
    public val authenticationTag: ByteArray,
)

// outputs: cek (content encryption key)
public typealias JweKeyGenerator = (headers: JweHeaders) -> ByteArray? // if null -> can't generate key -> can't encrypt
// outputs: encrypted key if needed, null if pre-shared (dir) or derived key (ecdh-es)
public typealias JweKeyEncryptor = (headers: JweHeaders, key: ByteArray) -> ByteArray?
// outputs: cek (content encryption key)
public typealias JweKeyDecryptor = (headers: JweHeaders, encryptedKey: ByteArray?) -> ByteArray? // if null -> can't decrypt

// a shared header only
public typealias JweContentEncryptor = (
    header: JweHeaders,
    key: ByteArray,
    plaintext: ByteArray,
    authenticatedData: ByteArray,
) -> JweCiphertext // iv, ciphertext, auth tag

public typealias JweContentDecryptor = (
    header: JweHeaders,
    key: ByteArray,
    ciphertext: JweCiphertext,
    authenticatedData: ByteArray,
) -> ByteArray

public enum class JweEncryptingMode {
    // requires to encrypt/decrypt all recipients - fail otherwise
    ALL,

    // requires to encrypt/decrypt at least one recipient, will try to encrypt/decrypt all recipients - fail otherwise
    AT_LEAST_ONCE,

    // requires to encrypt/decrypt at most one recipient, stop after at least one recipient is encrypted/decrypted - fail otherwise
    AT_MOST_ONCE,
}

@DelicateJoseApi
public inline fun JweContent.encrypt(
    mode: JweEncryptingMode,
    keyGenerator: JweKeyGenerator,
    keyEncryptor: JweKeyEncryptor,
    contentEncryptor: JweContentEncryptor,
): JweObject = TODO()

@DelicateJoseApi
public inline fun JweContent.Compact.encrypt(
    keyGenerator: JweKeyGenerator,
    keyEncryptor: JweKeyEncryptor,
    contentEncryptor: JweContentEncryptor,
): JweObject.Compact = TODO()

@DelicateJoseApi
public inline fun JweObject.decrypt(
    mode: JweEncryptingMode,
    keyDecryptor: JweKeyDecryptor,
    contentDecryptor: JweContentDecryptor,
): JweContent = TODO()

@DelicateJoseApi
public inline fun JweObject.Compact.decrypt(
    keyDecryptor: JweKeyDecryptor,
    contentDecryptor: JweContentDecryptor,
): JweContent.Compact = TODO()
