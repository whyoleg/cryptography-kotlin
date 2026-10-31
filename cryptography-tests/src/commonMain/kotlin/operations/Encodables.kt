/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.Decoder
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.coroutines.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.json.*
import kotlin.test.*

@Suppress("FunctionName")
fun <F : EncodingFormat> EncodingFormatSerializer(values: List<F>): KSerializer<F> {
    return EncodingFormatSerializer(values.associateBy { it.name })
}

private class EncodingFormatSerializer<F : EncodingFormat>(
    private val values: Map<String, F>,
) : KSerializer<F> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("dev.whyoleg.cryptography.materials.EncodingFormat", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: F) {
        encoder.encodeString(value.name)
    }

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): F {
        return values.getValue(decoder.decodeString())
    }
}

@Serializable
class TestEncodable<F : EncodingFormat>(
    val materials: List<TestMaterial<F>>,
    // original object, available only during generation (f.e. non-exportable keys)
    @Transient val encodable: Encodable<F>? = null,
)

@Serializable
class TestMaterial<F : EncodingFormat>(
    val format: F,
    val content: SerializableByteString,
    // `Invalid` means that decoding must fail
    val expected: ExpectedResult = ExpectedResult.Valid,
) {
    override fun toString(): String = "TestMaterial(format=$format, size=${content.size}, expected=$expected)"
}

@Suppress("UnusedReceiverParameter") // scoping
fun <F : EncodingFormat> TestInputValidator.material(
    format: F,
    content: ByteString,
    expected: ExpectedResult = ExpectedResult.Valid,
): TestMaterial<F> = TestMaterial(format, content, expected)

// where the encodable under test comes from, see `EncodableTestOperation`
sealed class KeySource {
    // original object (f.e. generated key)
    data object Generated : KeySource()

    // decoded from the material; `containsPublicKey` is declared by the format, see `TestEncodingFormatsBuilder`
    data class Decoded(val material: TestMaterial<*>, val containsPublicKey: Boolean) : KeySource()
}

// operations of a single encodable (key, parameters), see `TestEncodableCodec`
sealed class EncodableTestOperation : TestOperation {
    data object GenerateKey : EncodableTestOperation()

    // `containsPublicKey` is declared by the format, see `TestEncodingFormatsBuilder`
    data class DecodeFromByteString(val material: TestMaterial<*>, val containsPublicKey: Boolean) : EncodableTestOperation()

    data class EncodeToByteString(val format: EncodingFormat, val source: KeySource) : EncodableTestOperation()
}

// `expected` could be produced by another provider, so comparison should take into account possible differences
typealias EncodingCheck = (expected: ByteString, actual: ByteString) -> Unit

// Formats of a single encodable type, built by `encodingFormats`
class TestEncodingFormats<F : EncodingFormat> internal constructor(
    private val checks: Map<F, EncodingCheck>,
    // whether the encoded value contains the public key (f.e. JWK private key), `false` if not declared
    private val publicKeyPredicates: Map<F, (content: ByteString) -> Boolean>,
) {
    // used during generation, in the order of declaration
    val formats: List<F> = checks.keys.toList()

    val serializer: KSerializer<F> = EncodingFormatSerializer(formats)

    fun check(format: F, expected: ByteString, actual: ByteString): Unit = checks.getValue(format)(expected, actual)

    // `false` for invalid materials
    fun containsPublicKey(material: TestMaterial<F>): Boolean = try {
        publicKeyPredicates[material.format]?.invoke(material.content) ?: false
    } catch (_: Exception) {
        false
    }
}

@TestDsl
class TestEncodingFormatsBuilder<F : EncodingFormat> internal constructor() {
    private val checks = linkedMapOf<F, EncodingCheck>()
    private val publicKeyPredicates = mutableMapOf<F, (content: ByteString) -> Boolean>()

    // custom comparison
    fun format(
        format: F,
        containsPublicKey: ((content: ByteString) -> Boolean)? = null,
        check: EncodingCheck,
    ) {
        require(checks.put(format, check) == null) { "Format $format is already declared" }
        if (containsPublicKey != null) publicKeyPredicates[format] = containsPublicKey
    }

    // byte-exact comparison
    fun raw(format: F, size: Int? = null): Unit = format(format) { expected, actual ->
        if (size != null) assertEquals(size, actual.size, "${format.name} size")
        assertBytesEquals(expected, actual)
    }

    // DER and the same content in PEM, byte-exact comparison by default
    fun der(
        der: F,
        pem: F,
        pemLabel: PemLabel,
        sizes: Collection<Int>? = null,
        // checked on DER content, f.e. `::hasPrivateKeyInfoPublicKey`
        containsPublicKey: ((der: ByteString) -> Boolean)? = null,
        check: EncodingCheck = ::assertBytesEquals,
    ) {
        format(der, containsPublicKey) { expected, actual ->
            if (sizes != null) assertContains(sizes, actual.size, "${der.name} size")
            check(expected, actual)
        }
        format(pem, containsPublicKey?.let { { content -> it(PemDocument.decode(content).content) } }) { expected, actual ->
            assertPemEquals(expected, actual, pemLabel, check)
        }
    }

    // order of keys and optional keys could differ between providers
    fun jwk(format: F, vararg requiredKeys: String, containsPublicKey: Boolean = false): Unit = format(
        format = format,
        containsPublicKey = if (containsPublicKey) ({ true }) else null,
    ) { expected, actual ->
        assertJwkEquals(expected, actual, requiredKeys.toSet())
    }

    internal fun build(): TestEncodingFormats<F> = TestEncodingFormats(checks, publicKeyPredicates)
}

fun <F : EncodingFormat> encodingFormats(block: TestEncodingFormatsBuilder<F>.() -> Unit): TestEncodingFormats<F> =
    TestEncodingFormatsBuilder<F>().apply(block).build()

// Describes how to generate, decode and compare encodings of a single encodable type (keys, parameters)
class TestEncodableCodec<F : EncodingFormat, E : Encodable<F>>(
    val decoder: Decoder<F, E>,
    val formats: TestEncodingFormats<F>,
    // limitation of generation, decoding and encoding
    private val limitation: TestOperationLimitation<EncodableTestOperation>? = null,
) {
    val serializer: KSerializer<TestEncodable<F>> = TestEncodable.serializer(formats.serializer)

    // decodes all materials (checking that invalid materials are rejected), returns values with their source
    context(context: TestValidationContext)
    suspend fun decode(encodable: TestEncodable<F>): List<Pair<KeySource, E>> = buildList {
        @Suppress("UNCHECKED_CAST")
        (encodable.encodable as E?)?.let { add(KeySource.Generated to it) }
        encodable.materials.forEach { material ->
            val containsPublicKey = formats.containsPublicKey(material)
            val operation = EncodableTestOperation.DecodeFromByteString(material, containsPublicKey)
            val value = when (material.expected) {
                ExpectedResult.Valid      -> operationOrNull(operation, limitation) {
                    decoder.decodeFromByteString(material.format, material.content)
                }
                ExpectedResult.Invalid    -> {
                    expectFailure(operation, limitation) { val _ = decoder.decodeFromByteString(material.format, material.content) }
                    null
                }
                ExpectedResult.Acceptable -> try {
                    decoder.decodeFromByteString(material.format, material.content)
                } catch (cause: CancellationException) {
                    throw cause
                } catch (_: Throwable) {
                    null
                }
            }
            if (value != null) add(KeySource.Decoded(material, containsPublicKey) to value)
        }
    }

    // checks that `value` encodes into the same materials (only valid ones are checked)
    context(context: TestValidationContext)
    suspend fun validateEncoding(value: E, materials: List<TestMaterial<F>>, source: KeySource) {
        materials.forEach { material ->
            if (material.expected != ExpectedResult.Valid) return@forEach
            val actual = operationOrNull(EncodableTestOperation.EncodeToByteString(material.format, source), limitation) {
                value.encodeToByteString(material.format)
            } ?: return@forEach
            formats.check(material.format, material.content, actual)
        }
    }

    // decodes all materials and checks that every decoded value encodes into the same materials
    context(context: TestValidationContext)
    suspend fun decodeAndValidate(encodable: TestEncodable<F>): List<E> = decode(encodable).map { (source, value) ->
        validateEncoding(value, encodable.materials, source)
        value
    }

    context(context: TestValidationContext)
    suspend fun encode(value: E): TestEncodable<F> = TestEncodable(
        materials = formats.formats.mapNotNull { format ->
            operationOrNull(EncodableTestOperation.EncodeToByteString(format, KeySource.Generated), limitation) {
                TestMaterial(format, value.encodeToByteString(format))
            }
        },
        encodable = value,
    )

    context(context: TestValidationContext)
    suspend fun generate(generator: KeyGenerator<E>): E =
        operation(EncodableTestOperation.GenerateKey, limitation) { generator.generateKey() }
}

// codec of a part of a composite value (f.e. keys of a key pair, see `keyPairCodec`), single encodables are declared via `encodables`
fun <F : EncodingFormat, E : Encodable<F>> encodableCodec(
    decoder: Decoder<F, E>,
    // limitation of generation, decoding and encoding
    limitation: TestOperationLimitation<EncodableTestOperation>? = null,
    // formats used during generation, in the order of declaration
    formats: TestEncodingFormatsBuilder<F>.() -> Unit,
): TestEncodableCodec<F, E> = TestEncodableCodec(decoder, encodingFormats(formats), limitation)

// [encodable] -> V
class EncodableTestGroupValidator<F : EncodingFormat, E : Encodable<F>, V : TestInputValidator> internal constructor(
    val codec: TestEncodableCodec<F, E>,
    private val validator: TestValidatorScope.(values: List<E>) -> V,
) : TestGroupValidator<TestEncodable<F>, V>(codec.serializer) {
    context(context: TestValidationContext)
    override suspend fun createValidator(parameters: TestEncodable<F>): V {
        val values = codec.decodeAndValidate(parameters)
        // f.e. all materials are invalid, or limited
        if (values.isEmpty()) skipNode("No values available")
        return TestValidatorScope.validator(values)
    }
}

// [encodable] -> V
@Suppress("UnusedReceiverParameter") // scoping
fun <F : EncodingFormat, E : Encodable<F>, V : TestInputValidator> TestValidatorScope.encodables(
    decoder: Decoder<F, E>,
    // limitation of generation, decoding and encoding
    limitation: TestOperationLimitation<EncodableTestOperation>? = null,
    // formats used during generation, in the order of declaration
    formats: TestEncodingFormatsBuilder<F>.() -> Unit,
    validator: TestValidatorScope.(values: List<E>) -> V,
): EncodableTestGroupValidator<F, E, V> = EncodableTestGroupValidator(encodableCodec(decoder, limitation, formats), validator)

context(context: TestGenerationContext)
suspend fun <F : EncodingFormat, V : TestInputValidator> EncodableTestGroupValidator<F, *, V>.encodableGroup(
    vararg materials: TestMaterial<F>,
    id: String = context.generateChildId(),
    block: suspend context(TestGenerationContext) V.() -> Unit = {},
): Unit = group(TestEncodable(materials.toList()), id, block = block)

context(context: TestGenerationContext)
suspend fun <F : EncodingFormat, E : Encodable<F>, V : TestInputValidator> EncodableTestGroupValidator<F, E, V>.encodableGroup(
    value: E,
    id: String = context.generateChildId(),
    block: suspend context(TestGenerationContext) V.() -> Unit,
): Unit = group(codec.encode(value), id, block = block)

// f.e. symmetric keys
context(context: TestGenerationContext)
suspend fun <F : EncodingFormat, E : Encodable<F>, V : TestInputValidator> EncodableTestGroupValidator<F, E, V>.generateEncodableGroups(
    generator: KeyGenerator<E>,
    iterations: Int,
    block: suspend context(TestGenerationContext) V.(value: E) -> Unit,
) {
    repeat(iterations) {
        val value = codec.generate(generator)
        encodableGroup(value) { block(value) }
    }
}

// keys order and optional keys could differ between providers
fun assertJwkEquals(
    expected: ByteString,
    actual: ByteString,
    requiredKeys: Set<String>,
) {
    val expectedJson = Json.decodeFromString(JsonObject.serializer(), expected.decodeToString())
    val actualJson = Json.decodeFromString(JsonObject.serializer(), actual.decodeToString())

    assertTrue(expectedJson.keys.containsAll(requiredKeys), "JWK: missing required keys in expected: $requiredKeys")
    assertTrue(actualJson.keys.containsAll(requiredKeys), "JWK: missing required keys in actual: $requiredKeys")

    expectedJson.keys.intersect(actualJson.keys).forEach { key ->
        assertEquals(expectedJson[key], actualJson[key], "JWK.$key")
    }
}

fun assertPemEquals(
    expected: ByteString,
    actual: ByteString,
    label: PemLabel,
    assertContentEquals: (expected: ByteString, actual: ByteString) -> Unit = ::assertBytesEquals,
) {
    val expectedDocument = PemDocument.decode(expected)
    val actualDocument = PemDocument.decode(actual)

    assertEquals(label, expectedDocument.label, "PEM.label (expected)")
    assertEquals(label, actualDocument.label, "PEM.label (actual)")
    assertContentEquals(expectedDocument.content, actualDocument.content)
}

// version and `publicKey` field could differ between providers (RFC 5958)
fun assertPrivateKeyInfoEquals(
    expected: ByteString,
    actual: ByteString,
) {
    val expectedInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), expected.toByteArray())
    val actualInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), actual.toByteArray())

    assertEquals(expectedInfo.privateKeyAlgorithm, actualInfo.privateKeyAlgorithm, "PrivateKeyInfo.privateKeyAlgorithm")
    assertBytesEquals(ByteString(expectedInfo.privateKey), ByteString(actualInfo.privateKey)) { "PrivateKeyInfo.privateKey" }

    val expectedPublicKey = expectedInfo.publicKey
    val actualPublicKey = actualInfo.publicKey
    if (expectedPublicKey != null && actualPublicKey != null) {
        assertEquals(expectedPublicKey.unusedBits, actualPublicKey.unusedBits, "PrivateKeyInfo.publicKey.unusedBits")
        assertBytesEquals(ByteString(expectedPublicKey.byteArray), ByteString(actualPublicKey.byteArray)) { "PrivateKeyInfo.publicKey" }
    }
}

// RFC 5958 `publicKey` field of `PrivateKeyInfo`
fun hasPrivateKeyInfoPublicKey(der: ByteString): Boolean =
    Der.decodeFromByteArray(PrivateKeyInfo.serializer(), der.toByteArray()).publicKey != null
