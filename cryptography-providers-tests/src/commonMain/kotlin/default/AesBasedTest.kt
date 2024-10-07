/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

abstract class AesBasedTest<A : AES<*>>(
    private val algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : ProviderTest(provider), CipherTest {

    protected inner class AesTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: A,
        val keySize: BinarySize,
    ) : AlgorithmTestScope<A>(logger, context, provider, algorithm)

    protected fun runTestForEachKeySize(block: suspend AesTestScope.() -> Unit) = testAlgorithm(algorithmId) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.inBits)) return@generateSymmetricKeySize

            block(AesTestScope(logger, context, provider, algorithm, keySize))
        }
    }

    suspend fun AlgorithmTestScope<*>.assertCipherWithIvViaFunction(
        encryptor: AES.IvEncryptor,
        decryptor: AES.IvDecryptor,
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
private suspend fun AES.IvEncryptor.resetIv(context: TestContext): AES.IvEncryptor {
    if (context.provider.isJdk && this is AES.IvAuthenticatedEncryptor) encrypt(ByteString())
    return this
}
