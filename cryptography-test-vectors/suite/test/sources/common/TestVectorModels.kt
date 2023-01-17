@file:Suppress("ArrayInDataClass")

package dev.whyoleg.cryptography.test.vectors.suite

import kotlinx.serialization.*
import kotlin.jvm.*

interface TestVectorParameters
interface TestVectorData

@Serializable
@JvmInline
value class TestVectorParametersId(val value: String)

@Serializable
@JvmInline
value class TestVectorDataId(val value: String)

@Serializable
data class TestVectorReference(
    val parametersId: TestVectorParametersId,
    val dataId: TestVectorDataId,
)

@Serializable
data class Payload<T>(val data: T, val metadata: Map<String, String>)


typealias SerializableBuffer = @Contextual ByteArray

@Serializable
class DigestData(val data: SerializableBuffer, val digest: SerializableBuffer) : TestVectorData

@Serializable
data class KeyData(val formats: Map<String, SerializableBuffer>) : TestVectorData

inline fun KeyData(block: MutableMap<String, ByteArray>.() -> Unit): KeyData = KeyData(buildMap(block))

@Serializable
data class KeyPairData(val public: KeyData, val private: KeyData) : TestVectorData

@Serializable
data class CipherData(
    val keyReference: TestVectorReference,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
) : TestVectorData

@Serializable
data class AuthenticatedCipherData(
    val keyReference: TestVectorReference,
    val associatedData: SerializableBuffer?,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
) : TestVectorData

@Serializable
data class SignatureData(
    val keyReference: TestVectorReference,
    val data: SerializableBuffer,
    val signature: SerializableBuffer,
) : TestVectorData

@Serializable
data class KeyDerivationData(
    val key1Reference: TestVectorReference,
    val key2Reference: TestVectorReference,
    val sharedSecret: SerializableBuffer,
) : TestVectorData
