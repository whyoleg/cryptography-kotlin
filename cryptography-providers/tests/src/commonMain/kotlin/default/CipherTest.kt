/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
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
            resetIv(encryptor, decryptor)
            assertContentEquals(plaintext, decryptor.decrypt(ciphertext))

            resetIv(encryptor, decryptor)
            assertContentEquals(
                plaintext,
                decryptor.decryptingSource(Buffer(ciphertext).bufferedSource()).buffered().use { it.readByteString() }
            )

            resetIv(encryptor, decryptor)
            assertContentEquals(
                plaintext,
                Buffer().also { output ->
                    decryptor.decryptingSink(output.bufferedSink()).buffered().use { it.write(ciphertext) }
                }.readByteString()
            )
        }
    }

    suspend fun AlgorithmTestScope<*>.assertCipherWithIvViaFunction(
        encryptor: IvEncryptor,
        decryptor: IvDecryptor,
        ivSize: Int,
        plaintext: ByteString,
    ) {
        val iv = ByteString(CryptographyRandom.nextBytes(ivSize))
        buildList {
            resetIv(encryptor, decryptor)
            add(encryptor.encryptWithIv(iv, plaintext))

            resetIv(encryptor, decryptor)
            add(encryptor.encryptingSourceWithIv(iv, Buffer(plaintext).bufferedSource()).buffered().use { it.readByteString() })

            resetIv(encryptor, decryptor)
            add(
                Buffer().also { output ->
                    encryptor.encryptingSinkWithIv(iv, output.bufferedSink()).buffered().use { it.write(plaintext) }
                }.readByteString()
            )
        }.forEach { ciphertext ->
            resetIv(encryptor, decryptor)
            assertContentEquals(plaintext, decryptor.decryptWithIv(iv, ciphertext))

            resetIv(encryptor, decryptor)
            assertContentEquals(
                plaintext,
                decryptor.decryptingSourceWithIv(iv, Buffer(ciphertext).bufferedSource()).buffered().use { it.readByteString() }
            )

            resetIv(encryptor, decryptor)
            assertContentEquals(
                plaintext,
                Buffer().also { output ->
                    decryptor.decryptingSinkWithIv(iv, output.bufferedSink()).buffered().use { it.write(ciphertext) }
                }.readByteString()
            )
        }
    }

    // GCM and ChaCha20 mode on JDK has a check which tries to prevent reuse of the same IV with the same key.
    // we need to set random IV first to be able to reuse IV for different plaintext for the same key
    private suspend fun AlgorithmTestScope<*>.resetIv(encryptor: Encryptor, decryptor: Decryptor) {
        if (!context.provider.isJdk) return

        when (algorithm.id) {
            AES.GCM          -> {
                // just reset the IV
                encryptor.encrypt(ByteString())
            }
            ChaCha20Poly1305 -> {
                // the check about reusing IV in JDK 11 and 17 is too strict: it will check on decryption too...
                val initial = encryptor.encrypt(ByteString())
                encryptor.encrypt(ByteString()) // discarded
                decryptor.decrypt(initial)
            }
        }
    }
}
