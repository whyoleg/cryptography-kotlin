package dev.whyoleg.cryptography.test.vectors.suite

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.test.vectors.client.*
import io.ktor.util.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.*
import kotlin.reflect.*

class RemoteApi(
    private val algorithm: String,
    private val metadata: Map<String, String>,
) : TestVectorApi() {
    private fun storage(path: String) = RemoteStorageApi(algorithm, metadata, path)
    override val keys: TestVectorStorageApi = storage("keys")
    override val keyPairs: TestVectorStorageApi = storage("key-pairs")
    override val digests: TestVectorStorageApi = storage("digests")
    override val signatures: TestVectorStorageApi = storage("signatures")
    override val ciphers: TestVectorStorageApi = storage("ciphers")
}

private object SymmetricKeySizeSerializer : KSerializer<SymmetricKeySize> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("SymmetricKeySize", PrimitiveKind.INT)

    override fun deserialize(decoder: Decoder): SymmetricKeySize {
        return SymmetricKeySize(decoder.decodeInt().bits)
    }

    override fun serialize(encoder: Encoder, value: SymmetricKeySize) {
        encoder.encodeInt(value.value.bits)
    }
}

private object Base64ByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeBase64Bytes()
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeBase64())
    }
}

private val json = Json {
    encodeDefaults = true
    prettyPrint = true
    useAlternativeNames = false
    serializersModule = SerializersModule {
        contextual(SymmetricKeySizeSerializer)
        contextual(Base64ByteArraySerializer)
    }
}

@Serializable
private class Payload<T>(
    val content: T,
    val metadata: Map<String, String>,
)

private class RemoteStorageApi(
    private val algorithm: String,
    private val metadata: Map<String, String>,
    private val path: String,
) : TestVectorStorageApi() {
    private val cache = mutableMapOf<KType, KSerializer<Any?>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> serializer(type: KType): KSerializer<T> =
        cache.getOrPut(type) { json.serializersModule.serializer(type) } as KSerializer<T>

    private fun <T> encode(value: T, type: KType): ByteArray =
        json.encodeToString(
            Payload.serializer(serializer(type)),
            Payload(value, metadata)
        ).encodeToByteArray()

    private fun <T> decode(bytes: ByteArray, type: KType): T =
        json.decodeFromString(
            Payload.serializer<T>(serializer(type)),
            bytes.decodeToString()
        ).content //log metadata

    //TODO: add logging
    override suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String {
        return TestVectorsClient.saveParameters(algorithm, path, encode(parameters, type))
    }

    override suspend fun <T : TestVectorParameters> getParameters(type: KType): List<Pair<String, T>> {
        return TestVectorsClient.getParameters(algorithm, path).map { (id, bytes) ->
            id to decode<T>(bytes, type)
        }.toList()
    }

    override suspend fun <T : TestVectorData> saveData(parametersId: TestVectorParametersId, data: T, type: KType): String {
        return TestVectorsClient.saveData(algorithm, path, parametersId.value, encode(data, type))
    }

    override suspend fun <T : TestVectorData> getData(parametersId: TestVectorParametersId, type: KType): List<Pair<String, T>> {
        return TestVectorsClient.getData(algorithm, path, parametersId.value).map { (id, bytes) ->
            id to decode<T>(bytes, type)
        }.toList()
    }
}
