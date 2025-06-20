/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

interface CipherTest {
    suspend fun AlgorithmTestScope<*>.assertCipherViaFunction(
        encryptor: Encryptor,
        decryptor: Decryptor,
        plaintext: ByteString,
    ) {
        listOf(
            encryptor.encrypt(plaintext),
            encryptor.encryptingSource(Buffer(plaintext).bufferedSource()).buffered().use { it.readByteString() },
            Buffer().also { output ->
                encryptor.encryptingSink(output.bufferedSink()).buffered().use { it.write(plaintext) }
            }.readByteString(),
        ).forEach { ciphertext ->
            assertContentEquals(plaintext, decryptor.decrypt(ciphertext))
            assertContentEquals(
                plaintext,
                decryptor.decryptingSource(Buffer(ciphertext).bufferedSource()).buffered().use { it.readByteString() }
            )
            assertContentEquals(
                plaintext,
                Buffer().also { output ->
                    decryptor.decryptingSink(output.bufferedSink()).buffered().use { it.write(ciphertext) }
                }.readByteString()
            )
        }
    }
}
