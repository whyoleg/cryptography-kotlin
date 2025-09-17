/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

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

    suspend fun AlgorithmTestScope<*>.assertCipherWithIvViaFunction(
        encryptor: IvEncryptor,
        decryptor: IvDecryptor,
        ivSize: Int,
        plaintext: ByteString,
    ) {
        val iv = ByteString(CryptographyRandom.nextBytes(ivSize))
        listOf(
            encryptor.resetIv(context).encryptWithIv(iv, plaintext),
            encryptor.resetIv(context).encryptingSourceWithIv(iv, Buffer(plaintext).bufferedSource()).buffered()
                .use { it.readByteString() },
            Buffer().also { output ->
                encryptor.resetIv(context).encryptingSinkWithIv(iv, output.bufferedSink()).buffered().use { it.write(plaintext) }
            }.readByteString(),
        ).forEach { ciphertext ->
            assertContentEquals(plaintext, decryptor.decryptWithIv(iv, ciphertext))
            assertContentEquals(
                plaintext,
                decryptor.decryptingSourceWithIv(iv, Buffer(ciphertext).bufferedSource()).buffered().use { it.readByteString() }
            )
            assertContentEquals(
                plaintext,
                Buffer().also { output ->
                    decryptor.decryptingSinkWithIv(iv, output.bufferedSink()).buffered().use { it.write(ciphertext) }
                }.readByteString()
            )
        }
    }
}

// GCM mode on JDK has a check which tries to prevent reuse of the same IV with the same key.
// we need to set random IV first to be able to reuse IV for different plaintext for the same key
private suspend fun IvEncryptor.resetIv(context: TestContext): IvEncryptor {
    if (context.provider.isJdk && this is IvAuthenticatedEncryptor) encrypt(ByteString())
    return this
}
