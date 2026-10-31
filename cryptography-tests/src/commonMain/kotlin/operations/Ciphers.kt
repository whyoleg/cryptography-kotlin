/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

@Serializable
data class CipherTestData(
    val plaintext: SerializableByteString,
    val ciphertext: SerializableByteString,
    // explicit IV; for IV ciphers `null` means that IV is prepended to the ciphertext
    val iv: SerializableByteString? = null,
    val associatedData: SerializableByteString? = null,
    // `Invalid` means that decryption must fail
    val expected: ExpectedResult = ExpectedResult.Valid,
)

sealed class CipherTestOperation : TestOperation {
    data class Encrypt(val plaintextSize: Int, val ivSize: Int?, val associatedDataSize: Int?) : CipherTestOperation()
    data class Decrypt(val ciphertextSize: Int, val ivSize: Int?, val associatedDataSize: Int?) : CipherTestOperation()

    // decryption must fail: `reason` describes why (stored invalid ciphertext, tampered ciphertext/associated data)
    data class RejectCiphertext(val reason: String, val ciphertextSize: Int) : CipherTestOperation()
}

// Supports all kinds of encryptors/decryptors: plain, with IV, authenticated (with associated data) and both.
// Authenticated decryptors are additionally checked to reject tampered ciphertext and associated data.
class CipherTestDataValidator internal constructor(
    private val encryptors: List<Encryptor>,
    private val decryptors: List<Decryptor>,
    // size of IV which is prepended to the ciphertext when it's not provided explicitly (0 for ciphers without IV)
    private val ivSize: Int,
    // size of the ciphertext (without prepended IV) for the plaintext of the given size
    private val ciphertextSize: (plaintextSize: Int) -> Int,
    // encryption without explicit IV produces the same ciphertext (f.e. ECB); encryption with explicit IV is always deterministic
    private val deterministic: Boolean,
    internal val limitation: TestOperationLimitation<CipherTestOperation>? = null,
) : TestDataValidator<CipherTestData>(CipherTestData.serializer()) {
    context(context: TestValidationContext)
    override suspend fun validate(data: CipherTestData) {
        when (data.expected) {
            ExpectedResult.Valid      -> validateValid(data)
            ExpectedResult.Invalid    -> decryptors.forEach {
                it.assertRejected(data.iv, data.ciphertext, data.associatedData, "invalid ciphertext")
            }
            // nothing to check
            ExpectedResult.Acceptable -> {}
        }
    }

    private fun expectedCiphertextSize(plaintextSize: Int, iv: ByteString?): Int =
        ciphertextSize(plaintextSize) + (if (iv == null) ivSize else 0)

    context(context: TestValidationContext)
    private suspend fun validateValid(data: CipherTestData) {
        val (plaintext, ciphertext, iv, associatedData) = data
        assertEquals(expectedCiphertextSize(plaintext.size, iv), ciphertext.size, "Ciphertext size")

        // all API variants and derived negative checks are performed only for the first decryptor and encryptor
        decryptors.forEachIndexed { index, decryptor ->
            if (index != 0) {
                val decrypted = operation(CipherTestOperation.Decrypt(ciphertext.size, iv?.size, associatedData?.size), limitation) {
                    resetIv(decryptor)
                    decryptor.decrypt(iv, ciphertext, associatedData)
                }
                assertBytesEquals(plaintext, decrypted) { "Decryptor.decrypt #$index" }
                return@forEachIndexed
            }
            decryptor.assertDecrypted(iv, ciphertext, associatedData, plaintext)
            if (decryptor is AuthenticatedDecryptor) {
                // derived negative checks
                decryptor.assertRejected(iv, ciphertext.flipBit(), associatedData, "tampered ciphertext")
                decryptor.assertRejected(iv, ciphertext, associatedData?.tamper() ?: ByteString(0), "tampered associated data")
            }
        }

        encryptors.forEachIndexed { encryptorIndex, encryptor ->
            encryptor.encryptVariants(iv, plaintext, associatedData, allVariants = encryptorIndex == 0).forEachIndexed { index, generated ->
                assertEquals(expectedCiphertextSize(plaintext.size, iv), generated.size, "Generated ciphertext size #$index")
                if (iv != null || deterministic) {
                    assertBytesEquals(ciphertext, generated) { "Generated ciphertext #$index" }
                } else {
                    decryptors.firstOrNull()?.let { decryptor ->
                        val decrypted = operation(CipherTestOperation.Decrypt(generated.size, null, associatedData?.size), limitation) {
                            resetIv(decryptor)
                            decryptor.decrypt(null, generated, associatedData)
                        }
                        assertBytesEquals(plaintext, decrypted) { "Decrypted generated ciphertext #$index" }
                    }
                }
            }
        }
    }

    context(context: TestValidationContext)
    private suspend fun Decryptor.assertDecrypted(
        iv: ByteString?,
        ciphertext: ByteString,
        associatedData: ByteString?,
        plaintext: ByteString,
    ) {
        val operation = CipherTestOperation.Decrypt(ciphertext.size, iv?.size, associatedData?.size)
        val decrypted = operation(operation, limitation) {
            resetIv(this)
            decrypt(iv, ciphertext, associatedData)
        }
        assertBytesEquals(plaintext, decrypted) { "Decryptor.decrypt" }

        val viaSource = operationOrNull(
            operation = CreateFunctionTestOperation("DecryptingSource"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) {
            resetIv(this)
            decryptingSource(iv, Buffer(ciphertext).bufferedSource(), associatedData).buffered().use { it.readByteString() }
        }
        if (viaSource != null) assertBytesEquals(plaintext, viaSource) { "Decryptor.decryptingSource" }

        val viaSink = operationOrNull(
            operation = CreateFunctionTestOperation("DecryptingSink"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) {
            resetIv(this)
            val output = Buffer()
            decryptingSink(iv, output.bufferedSink(), associatedData).buffered().use { it.write(ciphertext) }
            output.readByteString()
        }
        if (viaSink != null) assertBytesEquals(plaintext, viaSink) { "Decryptor.decryptingSink" }
    }

    context(context: TestValidationContext)
    private suspend fun Decryptor.assertRejected(iv: ByteString?, ciphertext: ByteString, associatedData: ByteString?, reason: String) {
        expectFailure(CipherTestOperation.RejectCiphertext(reason, ciphertext.size), limitation) {
            resetIv(this)
            val _ = decrypt(iv, ciphertext, associatedData)
        }
    }

    context(context: TestValidationContext)
    private suspend fun Encryptor.encryptVariants(
        iv: ByteString?,
        plaintext: ByteString,
        associatedData: ByteString?,
        allVariants: Boolean,
    ): List<ByteString> = buildList {
        add(operation(CipherTestOperation.Encrypt(plaintext.size, iv?.size, associatedData?.size), limitation) {
            resetIv(this@encryptVariants)
            encrypt(iv, plaintext, associatedData)
        })
        if (!allVariants) return@buildList

        operationOrNull(
            operation = CreateFunctionTestOperation("EncryptingSource"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) {
            resetIv(this@encryptVariants)
            encryptingSource(iv, Buffer(plaintext).bufferedSource(), associatedData).buffered().use { it.readByteString() }
        }?.let(::add)

        operationOrNull(
            operation = CreateFunctionTestOperation("EncryptingSink"),
            limitation = { failsIfIncrementalFunctionsUnsupported() },
        ) {
            resetIv(this@encryptVariants)
            val output = Buffer()
            encryptingSink(iv, output.bufferedSink(), associatedData).buffered().use { it.write(plaintext) }
            output.readByteString()
        }?.let(::add)
    }
}

// [ciphertext]
@Suppress("UnusedReceiverParameter") // scoping
fun TestValidatorScope.ciphertexts(
    encryptors: List<Encryptor>,
    decryptors: List<Decryptor>,
    // size of IV which is prepended to the ciphertext when it's not provided explicitly (0 for ciphers without IV)
    ivSize: Int,
    // size of the ciphertext (without prepended IV) for the plaintext of the given size
    ciphertextSize: (plaintextSize: Int) -> Int,
    // encryption without explicit IV produces the same ciphertext (f.e. ECB); encryption with explicit IV is always deterministic
    deterministic: Boolean,
    limitation: TestOperationLimitation<CipherTestOperation>? = null,
): CipherTestDataValidator = CipherTestDataValidator(encryptors, decryptors, ivSize, ciphertextSize, deterministic, limitation)

context(context: TestGenerationContext)
suspend fun CipherTestDataValidator.ciphertext(
    plaintext: ByteString,
    ciphertext: ByteString,
    iv: ByteString? = null,
    associatedData: ByteString? = null,
    expected: ExpectedResult = ExpectedResult.Valid,
    id: String = context.generateChildId(),
): Unit = generate(id, CipherTestData(plaintext, ciphertext, iv, associatedData, expected))

context(context: TestGenerationContext)
suspend fun CipherTestDataValidator.generateCiphertexts(
    encryptor: Encryptor,
    plaintextSizes: List<Int>,
    // explicit IV is generated if not null
    ivSize: Int? = null,
    // associated data is generated if not null
    associatedDataSize: Int? = null,
): Unit = generateCiphertextsFor(
    encryptor = encryptor,
    plaintexts = plaintextSizes.map { ByteString(CryptographyRandom.nextBytes(it)) },
    ivSize = ivSize,
    associatedDataSize = associatedDataSize,
)

context(context: TestGenerationContext)
suspend fun CipherTestDataValidator.generateCiphertextsFor(
    encryptor: Encryptor,
    plaintexts: List<ByteString>,
    ivSize: Int? = null,
    associatedDataSize: Int? = null,
) {
    plaintexts.forEach { plaintext ->
        val iv = ivSize?.let { ByteString(CryptographyRandom.nextBytes(it)) }
        val associatedData = associatedDataSize?.let { ByteString(CryptographyRandom.nextBytes(it)) }
        ciphertext(
            plaintext = plaintext,
            ciphertext = operation(CipherTestOperation.Encrypt(plaintext.size, iv?.size, associatedData?.size), limitation) {
                encryptor.encrypt(iv, plaintext, associatedData)
            },
            iv = iv,
            associatedData = associatedData,
        )
    }
}

// random data of the given sizes, which is not a valid ciphertext (f.e. too short or not aligned)
context(context: TestGenerationContext)
suspend fun CipherTestDataValidator.invalidCiphertexts(vararg sizes: Int) {
    sizes.forEach { size ->
        ciphertext(
            plaintext = ByteString(),
            ciphertext = ByteString(CryptographyRandom.nextBytes(size)),
            expected = ExpectedResult.Invalid,
            id = "invalid-$size",
        )
    }
}

// ciphertext of another key, which must be rejected (f.e. by authenticated ciphers)
context(context: TestGenerationContext)
suspend fun CipherTestDataValidator.otherKeyCiphertext(otherKeyEncryptor: Encryptor) {
    val plaintext = ByteString(CryptographyRandom.nextBytes(100))
    ciphertext(
        plaintext = ByteString(),
        ciphertext = operation(CipherTestOperation.Encrypt(plaintext.size, null, null), limitation) {
            otherKeyEncryptor.encrypt(null, plaintext, null)
        },
        expected = ExpectedResult.Invalid,
        id = "other-key",
    )
}

// GCM, CCM and ChaCha20 on JDK have a check which prevents reuse of the same IV with the same key.
// Encryption with a random IV resets the check, and for ChaCha20 the check is done on decryption too (JDK 11 and 17).
// Non-empty input is used, as Safari doesn't support empty inputs.
// Must be called inside of the operation, as it uses the same provider primitives
private suspend fun resetIv(target: Encryptor): Unit = resetIvImpl(target)
private suspend fun resetIv(target: Decryptor): Unit = resetIvImpl(target)

private suspend fun resetIvImpl(target: Any) {
    if (target !is IvAuthenticatedCipher) return
    val input = ByteString(0)
    val initial = target.encrypt(input)
    val _ = target.encrypt(input)
    val _ = target.decrypt(initial)
}

// dispatch to the most specific operation; IV is checked first as `IvAuthenticated*` implements both

private suspend fun Encryptor.encrypt(iv: ByteString?, plaintext: ByteString, associatedData: ByteString?): ByteString = when {
    iv == null                       -> if (this is AuthenticatedEncryptor) encrypt(plaintext, associatedData) else encrypt(plaintext)
    this is IvAuthenticatedEncryptor -> encryptWithIv(iv, plaintext, associatedData)
    this is IvEncryptor              -> encryptWithIv(iv, plaintext)
    else                             -> error("Explicit IV is not supported by $this")
}

private fun Encryptor.encryptingSource(iv: ByteString?, plaintext: RawSource, associatedData: ByteString?): RawSource = when {
    iv == null                       -> if (this is AuthenticatedEncryptor) encryptingSource(
        plaintext,
        associatedData
    ) else encryptingSource(plaintext)
    this is IvAuthenticatedEncryptor -> encryptingSourceWithIv(iv, plaintext, associatedData)
    this is IvEncryptor              -> encryptingSourceWithIv(iv, plaintext)
    else                             -> error("Explicit IV is not supported by $this")
}

private fun Encryptor.encryptingSink(iv: ByteString?, ciphertext: RawSink, associatedData: ByteString?): RawSink = when {
    iv == null                       -> if (this is AuthenticatedEncryptor) encryptingSink(ciphertext, associatedData) else encryptingSink(
        ciphertext
    )
    this is IvAuthenticatedEncryptor -> encryptingSinkWithIv(iv, ciphertext, associatedData)
    this is IvEncryptor              -> encryptingSinkWithIv(iv, ciphertext)
    else                             -> error("Explicit IV is not supported by $this")
}

private suspend fun Decryptor.decrypt(iv: ByteString?, ciphertext: ByteString, associatedData: ByteString?): ByteString = when {
    iv == null                       -> if (this is AuthenticatedDecryptor) decrypt(ciphertext, associatedData) else decrypt(ciphertext)
    this is IvAuthenticatedDecryptor -> decryptWithIv(iv, ciphertext, associatedData)
    this is IvDecryptor              -> decryptWithIv(iv, ciphertext)
    else                             -> error("Explicit IV is not supported by $this")
}

private fun Decryptor.decryptingSource(iv: ByteString?, ciphertext: RawSource, associatedData: ByteString?): RawSource = when {
    iv == null                       -> if (this is AuthenticatedDecryptor) decryptingSource(
        ciphertext,
        associatedData
    ) else decryptingSource(ciphertext)
    this is IvAuthenticatedDecryptor -> decryptingSourceWithIv(iv, ciphertext, associatedData)
    this is IvDecryptor              -> decryptingSourceWithIv(iv, ciphertext)
    else                             -> error("Explicit IV is not supported by $this")
}

private fun Decryptor.decryptingSink(iv: ByteString?, plaintext: RawSink, associatedData: ByteString?): RawSink = when {
    iv == null                       -> if (this is AuthenticatedDecryptor) decryptingSink(plaintext, associatedData) else decryptingSink(
        plaintext
    )
    this is IvAuthenticatedDecryptor -> decryptingSinkWithIv(iv, plaintext, associatedData)
    this is IvDecryptor              -> decryptingSinkWithIv(iv, plaintext)
    else                             -> error("Explicit IV is not supported by $this")
}
