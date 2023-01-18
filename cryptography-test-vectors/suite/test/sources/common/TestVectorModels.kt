@file:Suppress("ArrayInDataClass")

package dev.whyoleg.cryptography.test.vectors.suite

import kotlinx.serialization.*
import kotlin.jvm.*

interface TestVectorParameters
interface TestVectorData

@Serializable
@JvmInline
value class TestVectorParametersId(val value: String) {
    override fun toString(): String = "P($value)"
}

@Serializable
@JvmInline
value class TestVectorDataId(val value: String) {
    override fun toString(): String = "D($value)"
}

@Serializable
data class TestVectorReference(
    val parametersId: TestVectorParametersId,
    val dataId: TestVectorDataId,
) {
    override fun toString(): String = "R(${parametersId.value} -> ${dataId.value})"
}


typealias SerializableBuffer = @Contextual ByteArray

@Serializable
data class DigestData(val data: SerializableBuffer, val digest: SerializableBuffer) : TestVectorData

@Serializable
data class KeyData(val formats: Map<String, SerializableBuffer>) : TestVectorData {
    override fun toString(): String = "KeyData(formats=${formats.mapValues { it.value.size.toString() }})"
}

inline fun KeyData(block: MutableMap<String, ByteArray>.() -> Unit): KeyData = KeyData(buildMap(block))

@Serializable
data class KeyPairData(val public: KeyData, val private: KeyData) : TestVectorData

@Serializable
data class CipherData(
    val keyReference: TestVectorReference,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
) : TestVectorData {
    override fun toString(): String {
        return "CipherData(keyReference=$keyReference, plaintext.size=${plaintext.size}, ciphertext.size=${ciphertext.size})"
    }
}

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
