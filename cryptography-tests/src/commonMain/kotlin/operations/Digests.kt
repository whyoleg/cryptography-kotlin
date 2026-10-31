/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

// digests have no invalid inputs, so there is no `expected` result
@Serializable
class DigestTestData(
    val message: SerializableByteString,
    val digest: SerializableByteString,
)

sealed class DigestTestOperation : TestOperation {
    data class Hash(val messageSize: Int) : DigestTestOperation()
}

class DigestTestDataValidator internal constructor(
    private val hasher: Hasher,
    private val digestSize: Int,
    internal val limitation: TestOperationLimitation<DigestTestOperation>? = null,
) : TestDataValidator<DigestTestData>(DigestTestData.serializer()) {
    context(context: TestValidationContext)
    override suspend fun validate(data: DigestTestData) {
        assertEquals(digestSize, data.digest.size, "Digest size")
        val digest = operation(DigestTestOperation.Hash(data.message.size), limitation) { hasher.hash(data.message) }
        assertBytesEquals(data.digest, digest) { "Hasher.hash(ByteString)" }
        assertBytesEquals(data.digest, hasher.hash(Buffer(data.message))) { "Hasher.hash(RawSource)" }

        val function = operationOrNull(
            operation = CreateFunctionTestOperation("HashFunction"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) { hasher.createHashFunction() } ?: return
        function.use {
            // the same function is reused, as `hash` resets it
            updateFunctionVariants.forEachIndexed { index, variant ->
                function.variant(data.message)
                assertBytesEquals(data.digest, function.hash()) { "HashFunction variant $index" }
            }

            // reset discards the state
            function.update(data.message)
            function.reset()
            function.update(data.message)
            assertBytesEquals(data.digest, function.hash()) { "HashFunction.reset" }
        }
    }
}

// [digest]
@Suppress("UnusedReceiverParameter") // scoping
fun TestValidatorScope.digests(
    hasher: Hasher,
    digestSize: Int,
    limitation: TestOperationLimitation<DigestTestOperation>? = null,
): DigestTestDataValidator = DigestTestDataValidator(hasher, digestSize, limitation)

context(context: TestGenerationContext)
suspend fun DigestTestDataValidator.digest(
    message: ByteString,
    digest: ByteString,
    id: String = context.generateChildId(),
): Unit = generate(id, DigestTestData(message, digest))

context(context: TestGenerationContext)
suspend fun DigestTestDataValidator.generateDigests(
    hasher: Hasher,
    messageSizes: List<Int>,
) {
    messageSizes.forEach { messageSize ->
        val message = ByteString(CryptographyRandom.nextBytes(messageSize))
        digest(message, operation(DigestTestOperation.Hash(messageSize), limitation) { hasher.hash(message) })
    }
}
