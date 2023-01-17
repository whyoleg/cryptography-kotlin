package dev.whyoleg.cryptography.test.vectors.client

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.content.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.flow.*

object TestVectorsClient {

    private val client = HttpClient {
        install(DefaultRequest) {
            port = 9000
        }
    }

    suspend fun saveMeta(algorithm: String, path: String, bytes: ByteArray): String =
        save("$algorithm/$path", bytes)

    fun getMeta(algorithm: String, path: String): Flow<Pair<String, ByteArray>> = get("$algorithm/$path")

    suspend fun saveData(algorithm: String, path: String, metaId: String, bytes: ByteArray): String =
        save("$algorithm/$path/$metaId/data", bytes)

    fun getData(algorithm: String, path: String, metaId: String): Flow<Pair<String, ByteArray>> = get("$algorithm/$path/$metaId/data")

    private suspend fun save(path: String, bytes: ByteArray) = client.post(path) {
        setBody(ByteArrayContent(bytes))
    }.bodyAsText()

    private fun get(path: String) = flow {
        val channel = client.get(path).bodyAsChannel()
        while (true) {
            val idLength = channel.readIntOrNull() ?: break
            val id = channel.readPacket(idLength).readText()
            val contentLength = channel.readInt()
            val content = channel.readPacket(contentLength).readBytes()
            emit(id to content)
        }
    }
}

private suspend fun ByteReadChannel.readIntOrNull(): Int? {
    val packet = readRemaining(4)
    if (packet.remaining == 0L) return null
    return packet.readInt()
}

//
//private val json = Json {
//    encodeDefaults = true
//    prettyPrint = true
//    useAlternativeNames = false
//    serializersModule = SerializersModule {
//        contextual(Base64ByteArraySerializer)
//    }
//}
//
//private object Base64ByteArraySerializer : KSerializer<ByteArray> {
//    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64", PrimitiveKind.STRING)
//
//    override fun deserialize(decoder: Decoder): ByteArray {
//        return decoder.decodeString().decodeBase64Bytes()
//    }
//
//    override fun serialize(encoder: Encoder, value: ByteArray) {
//        encoder.encodeString(value.encodeBase64())
//    }
//}
//
//class HttpApi(override val metadata: Map<String, String>) : Api {
//    override val keys: Api.SubApi<KeyData> = api("keys")
//    override val keyPairs: Api.SubApi<KeyPairData> = api("key-pairs")
//    override val digests: Api.SubApi<DigestData> = api("digests")
//    override val signatures: Api.SubApi<SignatureData> = api("signatures")
//    override val ciphers: Api.SubApi<CipherData> = api("ciphers")
//
//    private inline fun <reified T> api(path: String) = HttpSubApi<T>(path, metadata, serializer())
//
//    private class HttpSubApi<T>(
//        private val path: String,
//        private val metadata: Map<String, String>,
//        private val serializer: KSerializer<Payload<T>>,
//    ) : Api.SubApi<T> {
//
//        override suspend fun save(algorithm: String, params: String, data: T, metadata: Map<String, String>): String {
//            try {
//                val payload = Payload(data, this.metadata + metadata)
//                val bytes = json.encodeToString(serializer, payload).encodeToByteArray()
//                val id = client.post("$path/$algorithm/$params") {
//                    setBody(ByteArrayContent(bytes))
//                }.bodyAsText()
//                println("save: $path/$algorithm/$params -> $id | $metadata")
//                return id
//            } catch (cause: Throwable) {
//                println("save[FAILED]: $path/$algorithm/$params | $metadata")
//                throw cause
//            }
//        }
//
//        override suspend fun get(algorithm: String, params: String, id: String): Payload<T> {
//            try {
//                val text = client.get("$path/$algorithm/$params/$id").bodyAsText()
//                val payload = json.decodeFromString(serializer, text)
//                println("get: $path/$algorithm/$params/$id | ${payload.metadata}")
//                return payload
//            } catch (cause: Throwable) {
//                println("get[FAILED]: $path/$algorithm/$params/$id")
//                throw cause
//            }
//        }
//
//        override suspend fun getAll(algorithm: String, params: String): List<Payload<T>> {
//            println("getAll: $path/$algorithm/$params")
//            val channel = client.get("$path/$algorithm/$params").bodyAsChannel()
//            return buildList {
//                while (true) {
//                    val lengthPacket = channel.readRemaining(4)
//                    if (lengthPacket.remaining == 0L) break
//                    val length = lengthPacket.readInt()
//                    val bytes = channel.readPacket(length).readBytes().decodeToString()
//                    add(json.decodeFromString(serializer, bytes))
//                }
//            }
//        }
//    }
//}
