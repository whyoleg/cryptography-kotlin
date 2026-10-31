/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

@Serializable
data class SharedSecretTestData(
    val sharedSecret: SerializableByteString,
    // `Invalid` means that shared secret generation must fail (f.e. invalid public key)
    val expected: ExpectedResult = ExpectedResult.Valid,
)

sealed class SharedSecretTestOperation : TestOperation {
    data object GenerateSharedSecret : SharedSecretTestOperation()
    data object RejectSharedSecret : SharedSecretTestOperation()
}

class SharedSecretTestDataValidator internal constructor(
    // all possible ways to compute the shared secret
    private val computations: List<suspend () -> ByteString>,
    // `null` if the size is not fixed
    private val sharedSecretSize: Int?,
    internal val limitation: TestOperationLimitation<SharedSecretTestOperation>? = null,
) : TestDataValidator<SharedSecretTestData>(SharedSecretTestData.serializer()) {
    context(context: TestValidationContext)
    override suspend fun validate(data: SharedSecretTestData) {
        when (data.expected) {
            ExpectedResult.Valid      -> {
                if (sharedSecretSize != null) assertEquals(sharedSecretSize, data.sharedSecret.size, "Shared secret size")
                computations.forEachIndexed { index, computation ->
                    val sharedSecret = operation(SharedSecretTestOperation.GenerateSharedSecret, limitation) { computation() }
                    assertBytesEquals(data.sharedSecret, sharedSecret) { "Shared secret #$index" }
                }
            }
            ExpectedResult.Invalid    -> computations.forEach { computation ->
                expectFailure(SharedSecretTestOperation.RejectSharedSecret, limitation) { val _ = computation() }
            }
            // nothing to check
            ExpectedResult.Acceptable -> {}
        }
    }
}

// [shared secret] of private key of one pair with public key of another
@Suppress("UnusedReceiverParameter") // scoping
fun <Pub, Priv> TestValidatorScope.sharedSecrets(
    first: TestKeyPairs<Pub, Priv>,
    second: TestKeyPairs<Pub, Priv>,
    publicKeyGenerator: (Pub) -> SharedSecretGenerator<Priv>,
    privateKeyGenerator: (Priv) -> SharedSecretGenerator<Pub>,
    // `null` if the size is not fixed
    sharedSecretSize: Int?,
    limitation: TestOperationLimitation<SharedSecretTestOperation>? = null,
): SharedSecretTestDataValidator = SharedSecretTestDataValidator(
    computations = sharedSecretComputations(first, second, publicKeyGenerator, privateKeyGenerator),
    sharedSecretSize = sharedSecretSize,
    limitation = limitation,
)

// in both directions, via both public and private key generators.
// To keep the number of operations reasonable (keys are decoded from all formats),
// every key is used at least once, paired with the first key of the other kind
private fun <Pub, Priv> sharedSecretComputations(
    first: TestKeyPairs<Pub, Priv>,
    second: TestKeyPairs<Pub, Priv>,
    publicKeyGenerator: (Pub) -> SharedSecretGenerator<Priv>,
    privateKeyGenerator: (Priv) -> SharedSecretGenerator<Pub>,
): List<suspend () -> ByteString> = buildList {
    fun addAll(privateKeys: List<Priv>, publicKeys: List<Pub>) {
        val firstPrivateKey = privateKeys.firstOrNull() ?: return
        val firstPublicKey = publicKeys.firstOrNull() ?: return
        privateKeys.forEach { privateKey ->
            add { privateKeyGenerator(privateKey).generateSharedSecret(firstPublicKey) }
            add { publicKeyGenerator(firstPublicKey).generateSharedSecret(privateKey) }
        }
        publicKeys.drop(1).forEach { publicKey ->
            add { privateKeyGenerator(firstPrivateKey).generateSharedSecret(publicKey) }
            add { publicKeyGenerator(publicKey).generateSharedSecret(firstPrivateKey) }
        }
    }
    addAll(first.privateKeys, second.publicKeys)
    addAll(second.privateKeys, first.publicKeys)
}

context(context: TestGenerationContext)
suspend fun SharedSecretTestDataValidator.sharedSecret(
    sharedSecret: ByteString,
    expected: ExpectedResult = ExpectedResult.Valid,
    id: String = context.generateChildId(),
): Unit = generate(id, SharedSecretTestData(sharedSecret, expected))

context(context: TestGenerationContext)
suspend fun <K> SharedSecretTestDataValidator.generateSharedSecret(
    generator: SharedSecretGenerator<K>,
    otherKey: K,
): Unit = sharedSecret(operation(SharedSecretTestOperation.GenerateSharedSecret, limitation) { generator.generateSharedSecret(otherKey) })
