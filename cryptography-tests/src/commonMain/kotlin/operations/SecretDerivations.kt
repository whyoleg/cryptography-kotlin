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

// derivation has no invalid inputs, so there is no `expected` result
@Serializable
data class SecretDerivationTestData(
    val input: SerializableByteString,
    val secret: SerializableByteString,
)

sealed class SecretDerivationTestOperation : TestOperation {
    data class DeriveSecret(val inputSize: Int) : SecretDerivationTestOperation()
}

class SecretDerivationTestDataValidator internal constructor(
    private val derivation: SecretDerivation,
    private val secretSize: Int,
    internal val limitation: TestOperationLimitation<SecretDerivationTestOperation>? = null,
) : TestDataValidator<SecretDerivationTestData>(SecretDerivationTestData.serializer()) {
    context(context: TestValidationContext)
    override suspend fun validate(data: SecretDerivationTestData) {
        assertEquals(secretSize, data.secret.size, "Secret size")
        val secret =
            operation(SecretDerivationTestOperation.DeriveSecret(data.input.size), limitation) { derivation.deriveSecret(data.input) }
        assertBytesEquals(data.secret, secret) { "SecretDerivation.deriveSecret" }
        // derived negative check, only for big enough secrets, as for small ones collisions are likely (f.e. 1/256 for 1 byte)
        if (data.secret.size >= 8) {
            val tamperedInput = data.input.tamper()
            val tamperedSecret = operation(SecretDerivationTestOperation.DeriveSecret(tamperedInput.size), limitation) {
                derivation.deriveSecret(tamperedInput)
            }
            assertNotEquals(data.secret, tamperedSecret, "Secret for tampered input")
        }
    }
}

// [secret]
@Suppress("UnusedReceiverParameter") // scoping
fun TestValidatorScope.secrets(
    derivation: SecretDerivation,
    secretSize: Int,
    limitation: TestOperationLimitation<SecretDerivationTestOperation>? = null,
): SecretDerivationTestDataValidator = SecretDerivationTestDataValidator(derivation, secretSize, limitation)

context(context: TestGenerationContext)
suspend fun SecretDerivationTestDataValidator.secret(
    input: ByteString,
    secret: ByteString,
    id: String = context.generateChildId(),
): Unit = generate(id, SecretDerivationTestData(input, secret))

context(context: TestGenerationContext)
suspend fun SecretDerivationTestDataValidator.generateSecrets(
    derivation: SecretDerivation,
    inputSizes: List<Int>,
): Unit = generateSecretsFor(derivation, inputSizes.map { ByteString(CryptographyRandom.nextBytes(it)) })

context(context: TestGenerationContext)
suspend fun SecretDerivationTestDataValidator.generateSecretsFor(
    derivation: SecretDerivation,
    inputs: List<ByteString>,
) {
    inputs.forEach { input ->
        secret(input, operation(SecretDerivationTestOperation.DeriveSecret(input.size), limitation) { derivation.deriveSecret(input) })
    }
}
