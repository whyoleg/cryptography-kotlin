package dev.whyoleg.cryptography.test.api

import kotlinx.serialization.*

enum class Engine {
    JDK,
    WebCrypto,
    Apple
}

@Serializable
sealed class Platform {
    @Serializable
    object JVM : Platform()

    @Serializable //nodejs and browser
    data class JS(val kind: String) : Platform()

    @Serializable //macos, linux, etc
    data class Native(val kind: String) : Platform()
}

@Serializable
class EncodedId(val id: String)

@Serializable
data class EncodedData<T>(val platform: Platform, val engine: Engine, val data: T)

@Serializable
class EncodedCipher(val keyId: String, val plaintext: ByteArray, val ciphertext: ByteArray)

@Serializable
class EncodedSignature(val keyId: String, val data: ByteArray, val signature: ByteArray)

@Serializable
class EncodedDigest(val data: ByteArray, val digest: ByteArray)

@Serializable
data class EncodedKey(val keys: Map<String, ByteArray>)

@Serializable
data class EncodedKeyPair(val public: EncodedKey, val private: EncodedKey)
