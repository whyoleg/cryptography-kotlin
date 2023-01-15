package dev.whyoleg.cryptography.test.api

import kotlinx.serialization.*

interface Api {
    val metadata: Map<String, String>

    val keys: SubApi<KeyData>
    val keyPairs: SubApi<KeyPairData>
    val digests: SubApi<DigestData>
    val ciphers: SubApi<CipherData>
    val signatures: SubApi<SignatureData>

    interface SubApi<T> {
        suspend fun save(
            algorithm: String,
            params: String,
            data: T,
            metadata: Map<String, String> = emptyMap(),
        ): String

        suspend fun get(algorithm: String, params: String, id: String): Payload<T>

        //TODO: may be to replace with Flow?
        suspend fun getAll(algorithm: String, params: String): List<Payload<T>>
    }
}

@Serializable
data class Payload<T>(val data: T, val metadata: Map<String, String>)

@Serializable
data class KeyData(val formats: Map<String, SerializableBuffer>)

@Serializable
data class KeyPairData(val public: KeyData, val private: KeyData)

@Serializable
class DigestData(val data: SerializableBuffer, val digest: SerializableBuffer)

@Serializable
class CipherData(
    val keyId: String,
    val keyParams: String,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
)

@Serializable
class SignatureData(
    val keyId: String,
    val keyParams: String,
    val data: SerializableBuffer,
    val signature: SerializableBuffer,
)

typealias SerializableBuffer = @Contextual ByteArray
