package dev.whyoleg.cryptography.test.api

import kotlinx.serialization.*

typealias SerializableBuffer = @Contextual ByteArray

@Serializable
data class Payload<T>(val data: T, val metadata: Map<String, String>)

@Serializable
data class Reference(val metaId: String, val dataId: String)

@Serializable
class DigestData(val data: SerializableBuffer, val digest: SerializableBuffer)

@Serializable
data class KeyData(val formats: Map<String, SerializableBuffer>)

@Serializable
data class KeyPairData(val public: KeyData, val private: KeyData)

@Serializable
class CipherData(
    val keyReference: Reference,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
)

@Serializable
class AuthenticatedCipherData(
    val keyReference: Reference,
    val associatedData: SerializableBuffer?,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
)

@Serializable
class SignatureData(
    val keyReference: Reference,
    val data: SerializableBuffer,
    val signature: SerializableBuffer,
)

@Serializable
class KeyDerivationData(
    val key1Reference: Reference,
    val key2Reference: Reference,
    val sharedSecret: SerializableBuffer,
)
