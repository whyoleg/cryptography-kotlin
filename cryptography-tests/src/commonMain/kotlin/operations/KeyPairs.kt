/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.serialization.*

@Serializable
class KeyPairTestParameters<PubF : EncodingFormat, PrivF : EncodingFormat>(
    // could be empty for test cases where only private key is used
    val publicKey: TestEncodable<PubF>,
    // there could be no private key for test cases where only verification is performed
    val privateKey: TestEncodable<PrivF>? = null,
)

// all keys decoded from `KeyPairTestParameters`
class TestKeyPairs<Pub, Priv>(
    // includes public keys inferred from private keys
    val publicKeys: List<Pub>,
    val privateKeys: List<Priv>,
)

// operations of a key pair, see `KeyPairTestCodec`, operations of a single key are described by `EncodableTestOperation`
sealed class KeyPairTestOperation : TestOperation {
    data object GenerateKeyPair : KeyPairTestOperation()

    // `source` is the source of the private key
    data class GetPublicKey(val source: KeySource) : KeyPairTestOperation()
}

class KeyPairTestCodec<PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>>(
    val publicKey: TestEncodableCodec<PubF, Pub>,
    val privateKey: TestEncodableCodec<PrivF, Priv>,
    // `null` if the algorithm doesn't support getting public key from private key
    private val getPublicKey: (suspend (Priv) -> Pub)?,
    // limitation of generation and getting public key from private key
    private val limitation: TestOperationLimitation<KeyPairTestOperation>? = null,
) {
    val serializer: KSerializer<KeyPairTestParameters<PubF, PrivF>> =
        KeyPairTestParameters.serializer(publicKey.formats.serializer, privateKey.formats.serializer)

    // decodes keys from all materials and checks encodings
    context(context: TestValidationContext)
    suspend fun decode(parameters: KeyPairTestParameters<PubF, PrivF>): TestKeyPairs<Pub, Priv> {
        val publicKeysWithSource = publicKey.decode(parameters.publicKey)
        val privateKeysWithSource = parameters.privateKey?.let { privateKey.decode(it) }.orEmpty()
        val inferredPublicKeys = when (val getPublicKey = getPublicKey) {
            null -> emptyList()
            else -> privateKeysWithSource.mapNotNull { (source, key) ->
                operationOrNull(KeyPairTestOperation.GetPublicKey(source), limitation) { source to getPublicKey(key) }
            }
        }
        val allPublicKeysWithSource = publicKeysWithSource + inferredPublicKeys

        allPublicKeysWithSource.forEach { (source, key) ->
            publicKey.validateEncoding(key, parameters.publicKey.materials, source)
        }
        parameters.privateKey?.let { materials ->
            privateKeysWithSource.forEach { (source, key) ->
                privateKey.validateEncoding(key, materials.materials, source)
            }
        }

        return TestKeyPairs(
            publicKeys = allPublicKeysWithSource.map { it.second },
            privateKeys = privateKeysWithSource.map { it.second },
        )
    }

    context(context: TestValidationContext)
    suspend fun encode(publicKey: Pub, privateKey: Priv): KeyPairTestParameters<PubF, PrivF> = KeyPairTestParameters(
        publicKey = this.publicKey.encode(publicKey),
        privateKey = this.privateKey.encode(privateKey),
    )

    context(context: TestValidationContext)
    suspend fun <KP> generate(generator: KeyGenerator<KP>): KP =
        operation(KeyPairTestOperation.GenerateKeyPair, limitation) { generator.generateKey() }
}

fun <PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>> keyPairCodec(
    publicKey: TestEncodableCodec<PubF, Pub>,
    privateKey: TestEncodableCodec<PrivF, Priv>,
    // `null` if the algorithm doesn't support getting public key from private key
    getPublicKey: (suspend (Priv) -> Pub)?,
    // limitation of generation and getting public key from private key
    limitation: TestOperationLimitation<KeyPairTestOperation>? = null,
): KeyPairTestCodec<PubF, Pub, PrivF, Priv> = KeyPairTestCodec(publicKey, privateKey, getPublicKey, limitation)

// [key pair] -> V
class KeyPairTestGroupValidator<PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>, V : TestInputValidator> internal constructor(
    val codec: KeyPairTestCodec<PubF, Pub, PrivF, Priv>,
    private val validator: TestValidatorScope.(publicKeys: List<Pub>, privateKeys: List<Priv>) -> V,
) : TestGroupValidator<KeyPairTestParameters<PubF, PrivF>, V>(codec.serializer) {
    context(context: TestValidationContext)
    override suspend fun createValidator(parameters: KeyPairTestParameters<PubF, PrivF>): V {
        val keys = codec.decode(parameters)
        // f.e. all materials are invalid, or limited
        if (keys.publicKeys.isEmpty() && keys.privateKeys.isEmpty()) skipNode("No keys available")
        return TestValidatorScope.validator(keys.publicKeys, keys.privateKeys)
    }
}

// [key pair] -> V
@Suppress("UnusedReceiverParameter") // scoping
fun <PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>, V : TestInputValidator> TestValidatorScope.keyPairs(
    codec: KeyPairTestCodec<PubF, Pub, PrivF, Priv>,
    validator: TestValidatorScope.(publicKeys: List<Pub>, privateKeys: List<Priv>) -> V,
): KeyPairTestGroupValidator<PubF, Pub, PrivF, Priv, V> =
    KeyPairTestGroupValidator(codec, validator)

@Suppress("UnusedReceiverParameter") // scoping
fun <PubF : EncodingFormat, PrivF : EncodingFormat> TestInputValidator.keyPair(
    publicKey: TestMaterial<PubF>?,
    privateKey: TestMaterial<PrivF>?,
): KeyPairTestParameters<PubF, PrivF> = KeyPairTestParameters(
    publicKey = TestEncodable(listOfNotNull(publicKey)),
    privateKey = privateKey?.let { TestEncodable(listOf(it)) },
)

context(context: TestGenerationContext)
suspend fun <PubF : EncodingFormat, PrivF : EncodingFormat, V : TestInputValidator> KeyPairTestGroupValidator<PubF, *, PrivF, *, V>.keyPairGroup(
    publicKey: TestEncodable<PubF>,
    privateKey: TestEncodable<PrivF>?,
    id: String = context.generateChildId(),
    block: suspend context(TestGenerationContext) V.() -> Unit,
): Unit = group(KeyPairTestParameters(publicKey, privateKey), id, block = block)

context(context: TestGenerationContext)
suspend fun <PubF : EncodingFormat, PrivF : EncodingFormat, V : TestInputValidator> KeyPairTestGroupValidator<PubF, *, PrivF, *, V>.keyPairGroup(
    publicKey: TestMaterial<PubF>?,
    privateKey: TestMaterial<PrivF>?,
    id: String = context.generateChildId(),
    block: suspend context(TestGenerationContext) V.() -> Unit = {},
): Unit = group(keyPair(publicKey, privateKey), id, block = block)

context(context: TestGenerationContext)
suspend fun <KP, PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>, V : TestInputValidator>
        KeyPairTestGroupValidator<PubF, Pub, PrivF, Priv, V>.generateKeyPairGroups(
    generator: KeyGenerator<KP>,
    iterations: Int,
    publicKey: (KP) -> Pub,
    privateKey: (KP) -> Priv,
    block: suspend context(TestGenerationContext) V.(keyPair: KP) -> Unit,
) {
    repeat(iterations) {
        val keyPair = codec.generate(generator)
        group(codec.encode(publicKey(keyPair), privateKey(keyPair))) { block(keyPair) }
    }
}

// key agreement: [first key pair, second key pair] -> V

@Serializable
class KeyAgreementTestParameters<PubF : EncodingFormat, PrivF : EncodingFormat>(
    val first: KeyPairTestParameters<PubF, PrivF>,
    val second: KeyPairTestParameters<PubF, PrivF>,
)

class KeyAgreementTestGroupValidator<PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>, V : TestInputValidator> internal constructor(
    val codec: KeyPairTestCodec<PubF, Pub, PrivF, Priv>,
    private val validator: TestValidatorScope.(first: TestKeyPairs<Pub, Priv>, second: TestKeyPairs<Pub, Priv>) -> V,
) : TestGroupValidator<KeyAgreementTestParameters<PubF, PrivF>, V>(
    KeyAgreementTestParameters.serializer(codec.publicKey.formats.serializer, codec.privateKey.formats.serializer)
) {
    context(context: TestValidationContext)
    override suspend fun createValidator(parameters: KeyAgreementTestParameters<PubF, PrivF>): V {
        val first = codec.decode(parameters.first)
        val second = codec.decode(parameters.second)
        val hasPair = (first.privateKeys.isNotEmpty() && second.publicKeys.isNotEmpty()) ||
                (second.privateKeys.isNotEmpty() && first.publicKeys.isNotEmpty())
        // f.e. all materials are invalid, or limited
        if (!hasPair) skipNode("No key pairs available for key agreement")
        return TestValidatorScope.validator(first, second)
    }
}

// [first key pair, second key pair] -> V
@Suppress("UnusedReceiverParameter") // scoping
fun <PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>, V : TestInputValidator> TestValidatorScope.keyAgreements(
    codec: KeyPairTestCodec<PubF, Pub, PrivF, Priv>,
    validator: TestValidatorScope.(first: TestKeyPairs<Pub, Priv>, second: TestKeyPairs<Pub, Priv>) -> V,
): KeyAgreementTestGroupValidator<PubF, Pub, PrivF, Priv, V> =
    KeyAgreementTestGroupValidator(codec, validator)

context(context: TestGenerationContext)
suspend fun <PubF : EncodingFormat, PrivF : EncodingFormat, V : TestInputValidator> KeyAgreementTestGroupValidator<PubF, *, PrivF, *, V>.keyAgreementGroup(
    first: KeyPairTestParameters<PubF, PrivF>,
    second: KeyPairTestParameters<PubF, PrivF>,
    id: String = context.generateChildId(),
    block: suspend context(TestGenerationContext) V.() -> Unit,
): Unit = group(KeyAgreementTestParameters(first, second), id, block = block)

context(context: TestGenerationContext)
suspend fun <KP, PubF : EncodingFormat, Pub : Encodable<PubF>, PrivF : EncodingFormat, Priv : Encodable<PrivF>, V : TestInputValidator>
        KeyAgreementTestGroupValidator<PubF, Pub, PrivF, Priv, V>.generateKeyAgreementGroups(
    generator: KeyGenerator<KP>,
    iterations: Int,
    publicKey: (KP) -> Pub,
    privateKey: (KP) -> Priv,
    block: suspend context(TestGenerationContext) V.(first: KP, second: KP) -> Unit,
) {
    repeat(iterations) {
        val first = codec.generate(generator)
        val second = codec.generate(generator)
        keyAgreementGroup(
            first = codec.encode(publicKey(first), privateKey(first)),
            second = codec.encode(publicKey(second), privateKey(second)),
        ) { block(first, second) }
    }
}

// JDK without BouncyCastle can't compute the public key from the private key,
// so it's available only for generated keys and keys decoded from materials containing it.
// Affects getting the public key and encoding the private key to JWK (which contains the public key).
fun TestLimitationScope.failsIfPublicKeyIsNotDerivable(source: KeySource): TestLimitation? = when (source) {
    is KeySource.Decoded if provider.isJdkDefault && !source.containsPublicKey
         -> fails("Getting public key from private key is not supported in JDK without BouncyCastle")
    else -> null
}
