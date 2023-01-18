package dev.whyoleg.cryptography.test.vectors.suite.api

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.test.support.*
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

class ServerBasedApi(
    private val algorithm: String,
    private val metadata: Map<String, String>,
    private val testLoggingContext: TestLoggingContext,
) : TestVectorApi() {
    private fun api(storageName: String): TestVectorStorageApi = RemoteStorageApi(algorithm, metadata, storageName, testLoggingContext)
    override val keys: TestVectorStorageApi = api("keys")
    override val keyPairs: TestVectorStorageApi = api("key-pairs")
    override val digests: TestVectorStorageApi = api("digests")
    override val signatures: TestVectorStorageApi = api("signatures")
    override val ciphers: TestVectorStorageApi = api("ciphers")
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
        contextual(Base64ByteArraySerializer)
    }
}

@Serializable
private class Payload<T>(
    val metadata: Map<String, String>,
    val content: T,
)

private class RemoteStorageApi(
    private val algorithm: String,
    private val metadata: Map<String, String>,
    storageName: String,
    testLoggingContext: TestLoggingContext,
) : TestVectorStorageApi(storageName, testLoggingContext) {
    private val cache = mutableMapOf<KType, KSerializer<Any?>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> serializer(type: KType): KSerializer<T> =
        cache.getOrPut(type) { json.serializersModule.serializer(type) } as KSerializer<T>

    private fun <T> encode(value: T, type: KType): ByteArray =
        json.encodeToString(
            Payload.serializer(serializer(type)),
            Payload(metadata, value)
        ).encodeToByteArray()

    private fun <T> decode(id: String, bytes: ByteArray, type: KType): Triple<String, T, Map<String, String>> {
        val payload = json.decodeFromString(
            Payload.serializer<T>(serializer(type)),
            bytes.decodeToString()
        )
        return Triple(id, payload.content, payload.metadata)
    }

    override suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String {
        return TestVectorsClient.saveParameters(algorithm, storageName, encode(parameters, type))
    }

    override suspend fun <T : TestVectorParameters> getParameters(type: KType): List<Triple<String, T, Map<String, String>>> {
        return TestVectorsClient.getParameters(algorithm, storageName).map { (id, bytes) ->
            decode<T>(id, bytes, type)
        }.toList()
    }

    override suspend fun <T : TestVectorData> saveData(parametersId: TestVectorParametersId, data: T, type: KType): String {
        return TestVectorsClient.saveData(algorithm, storageName, parametersId.value, encode(data, type))
    }

    override suspend fun <T : TestVectorData> getData(
        parametersId: TestVectorParametersId,
        type: KType,
    ): List<Triple<String, T, Map<String, String>>> {
        return TestVectorsClient.getData(algorithm, storageName, parametersId.value).map { (id, bytes) ->
            decode<T>(id, bytes, type)
        }.toList()
    }
}
