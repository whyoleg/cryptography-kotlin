/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.coroutines.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

@Serializable
data class SignatureTestData(
    val message: SerializableByteString,
    val signature: SerializableByteString,
    val expected: ExpectedResult = ExpectedResult.Valid,
)

sealed class SignatureTestOperation : TestOperation {
    abstract val messageSize: Int

    data class GenerateSignature(override val messageSize: Int) : SignatureTestOperation()
    data class VerifySignature(override val messageSize: Int) : SignatureTestOperation()

    // for deterministic signature schemes generated signature must be equal to the stored one
    data class ReproduceSignature(override val messageSize: Int) : SignatureTestOperation()

    // verification must fail: `reason` describes why (stored invalid signature, tampered signature/message)
    data class RejectSignature(val reason: String, override val messageSize: Int) : SignatureTestOperation()
}

class SignatureTestDataValidator internal constructor(
    private val verifiers: List<SignatureVerifier>,
    private val generators: List<SignatureGenerator>,
    private val signatureSizes: Iterable<Int>,
    // for deterministic signature schemes generated signatures must be equal to stored ones
    private val deterministic: Boolean,
    internal val limitation: TestOperationLimitation<SignatureTestOperation>? = null,
) : TestDataValidator<SignatureTestData>(SignatureTestData.serializer()) {
    context(context: TestValidationContext)
    override suspend fun validate(data: SignatureTestData) {
        when (data.expected) {
            ExpectedResult.Valid      -> validateValid(data.message, data.signature)
            ExpectedResult.Invalid    -> verifiers.forEach { it.assertRejected(data.message, data.signature, "invalid signature") }
            ExpectedResult.Acceptable -> verifiers.forEach { it.assertConsistent(data.message, data.signature) }
        }
    }

    // To keep the number of operations reasonable (keys are decoded from all formats),
    // all API variants and derived negative checks are performed only for the first verifier and generator,
    // others are checked with a single operation
    context(context: TestValidationContext)
    private suspend fun validateValid(message: ByteString, signature: ByteString) {
        assertContains(signatureSizes, signature.size, "Signature size")

        verifiers.forEachIndexed { index, verifier ->
            if (index == 0) {
                verifier.assertAccepted(message, signature)
                // derived negative checks
                verifier.assertRejected(message, signature.flipBit(), "tampered signature")
                verifier.assertRejected(message.tamper(), signature, "tampered message")
                // malformed signatures, `tryVerify` must return `false` instead of throwing
                verifier.assertRejected(message, ByteString(), "empty signature")
                verifier.assertRejected(message, signature.substring(0, signature.size - 1), "truncated signature")
                // f.e. for DSA/ECDSA/EdDSA values are out of range, for RSA bigger than the modulus
                verifier.assertRejected(message, ByteString(ByteArray(signature.size) { -1 }), "out of range signature")
            } else {
                operation(SignatureTestOperation.VerifySignature(message.size), limitation) { verifier.verifySignature(message, signature) }
            }
        }

        generators.forEachIndexed { generatorIndex, generator ->
            val signatures = buildList {
                add(operation(SignatureTestOperation.GenerateSignature(message.size), limitation) { generator.generateSignature(message) })
                if (generatorIndex != 0) return@buildList
                val function = operationOrNull(
                    operation = CreateFunctionTestOperation("SignFunction"),
                    limitation = { failsIfIncrementalFunctionsUnsupported() },
                ) { generator.createSignFunction() }
                function?.use {
                    updateFunctionVariants.forEach { variant ->
                        function.reset()
                        function.variant(message)
                        add(function.sign())
                    }
                }
            }
            signatures.forEachIndexed { index, generated ->
                assertContains(signatureSizes, generated.size, "Generated signature size")
                val reproduced = deterministic && operationOrNull(SignatureTestOperation.ReproduceSignature(message.size), limitation) {
                    assertBytesEquals(signature, generated) { "Generated signature #$generatorIndex/$index" }
                } != null
                // if the signature can't be reproduced, it's at least verifiable
                if (!reproduced) verifiers.firstOrNull()?.let { verifier ->
                    operation(SignatureTestOperation.VerifySignature(message.size), limitation) {
                        verifier.verifySignature(
                            message,
                            generated
                        )
                    }
                }
            }
        }
    }

    context(context: TestValidationContext)
    private suspend fun SignatureVerifier.assertAccepted(message: ByteString, signature: ByteString) {
        operation(SignatureTestOperation.VerifySignature(message.size), limitation) { verifySignature(message, signature) }
        assertTrue(tryVerifySignature(message, signature), "SignatureVerifier.tryVerifySignature")
        verifySignature(Buffer(message), signature)

        val function = operationOrNull(
            operation = CreateFunctionTestOperation("VerifyFunction"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) { createVerifyFunction() } ?: return
        function.use {
            updateFunctionVariants.forEachIndexed { index, variant ->
                function.reset()
                function.variant(message)
                assertTrue(function.tryVerify(signature), "VerifyFunction.tryVerify variant $index")
                function.reset()
                function.variant(message)
                function.verify(signature)
            }
        }
    }

    context(context: TestValidationContext)
    private suspend fun SignatureVerifier.assertRejected(message: ByteString, signature: ByteString, reason: String) {
        val operation = SignatureTestOperation.RejectSignature(reason, message.size)
        expectFailure(operation, limitation) { verifySignature(message, signature) }
        expectFalse(operation, limitation) { tryVerifySignature(message, signature) }
    }

    // for `Acceptable` signatures, `verify` and `tryVerify` must agree
    private suspend fun SignatureVerifier.assertConsistent(message: ByteString, signature: ByteString) {
        val verified = try {
            verifySignature(message, signature)
            true
        } catch (cause: CancellationException) {
            throw cause
        } catch (_: Throwable) {
            false
        }
        assertEquals(verified, tryVerifySignature(message, signature), "verifySignature and tryVerifySignature must agree")
    }
}

// [signature]
@Suppress("UnusedReceiverParameter") // scoping
fun TestValidatorScope.signatures(
    verifiers: List<SignatureVerifier>,
    generators: List<SignatureGenerator>,
    signatureSizes: Iterable<Int>,
    // for deterministic signature schemes generated signatures must be equal to stored ones
    deterministic: Boolean,
    limitation: TestOperationLimitation<SignatureTestOperation>? = null,
): SignatureTestDataValidator = SignatureTestDataValidator(verifiers, generators, signatureSizes, deterministic, limitation)

context(context: TestGenerationContext)
suspend fun SignatureTestDataValidator.signature(
    message: ByteString,
    signature: ByteString,
    expected: ExpectedResult = ExpectedResult.Valid,
    id: String = context.generateChildId(),
): Unit = generate(id, SignatureTestData(message, signature, expected))

context(context: TestGenerationContext)
suspend fun SignatureTestDataValidator.generateSignatures(
    generator: SignatureGenerator,
    messageSizes: List<Int>,
) {
    messageSizes.forEach { messageSize ->
        val message = ByteString(CryptographyRandom.nextBytes(messageSize))
        signature(
            message = message,
            signature = operation(
                SignatureTestOperation.GenerateSignature(messageSize),
                limitation
            ) { generator.generateSignature(message) },
        )
    }
}

// signature of another key, which must be rejected
context(context: TestGenerationContext)
suspend fun SignatureTestDataValidator.otherKeySignature(otherKeyGenerator: SignatureGenerator) {
    val message = ByteString(CryptographyRandom.nextBytes(100))
    signature(
        message = message,
        signature = operation(
            SignatureTestOperation.GenerateSignature(message.size),
            limitation
        ) { otherKeyGenerator.generateSignature(message) },
        expected = ExpectedResult.Invalid,
        id = "other-key",
    )
}
