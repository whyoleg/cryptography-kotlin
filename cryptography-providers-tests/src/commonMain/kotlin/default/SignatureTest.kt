/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.tests.api.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.test.*

interface SignatureTest {
    suspend fun AlgorithmTestScope<*>.assertSignaturesViaFunction(
        signatureGenerator: SignatureGenerator,
        signatureVerifier: SignatureVerifier,
        data: ByteString,
    ) {
        val chunked: UpdateFunction. () -> Unit = {
            val steps = 10
            var step = data.size / steps
            if (step == 0) step = data.size
            var start = 0
            while (start < data.size) {
                update(data, start, minOf(data.size, start + step))
                start += step
            }
        }
        val viaSource: UpdateFunction. () -> Unit = {
            updatingSource(Buffer(data).bufferedSource()).buffered().use {
                assertContentEquals(data, it.readByteString())
            }
        }
        val viaSink: UpdateFunction. () -> Unit = {
            val output = Buffer()
            updatingSink(output.bufferedSink()).buffered().use { it.write(data) }
            assertContentEquals(data, output.readByteString())
        }

        fun signature(block: UpdateFunction. () -> Unit) = signatureGenerator.createSignFunction().use {
            it.block()
            it.sign()
        }

        fun tryVerify(signature: ByteString, block: UpdateFunction. () -> Unit) = signatureVerifier.createVerifyFunction().use {
            it.block()
            it.tryVerify(signature)
        }

        listOf(
            signatureGenerator.generateSignature(data),
            signature(chunked),
            signature(viaSource),
            signature(viaSink),
        ).forEach { signature ->
            assertTrue(signatureVerifier.tryVerifySignature(data, signature))
            assertTrue(tryVerify(signature, chunked))
            assertTrue(tryVerify(signature, viaSource))
            assertTrue(tryVerify(signature, viaSink))
        }
    }
}
