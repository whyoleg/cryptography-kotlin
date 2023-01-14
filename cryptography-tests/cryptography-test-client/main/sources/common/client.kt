package dev.whyoleg.cryptography.test.client

import dev.whyoleg.cryptography.test.api.*
import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.content.*
import io.ktor.util.*
import io.ktor.utils.io.core.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.*

private val client = HttpClient {
    install(DefaultRequest) {
        port = 9000
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

private object Base64ByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeBase64Bytes()
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeBase64())
    }
}

class HttpApi(private val metadata: Map<String, String>) : Api {
    private inline fun <reified T> api(path: String) = HttpSubApi<T>(path, serializer())

    override val keys: Api.SubApi<KeyData> = api("keys")
    override val keyPairs: Api.SubApi<KeyPairData> = api("key-pairs")
    override val digests: Api.SubApi<DigestData> = api("digests")
    override val signatures: Api.SubApi<SignatureData> = api("signatures")
    override val ciphers: Api.SubApi<CipherData> = api("ciphers")

    inner class HttpSubApi<T> internal constructor(
        private val path: String,
        private val serializer: KSerializer<Payload<T>>,
    ) : Api.SubApi<T> {

        override suspend fun save(algorithm: String, params: String, data: T, metadata: Map<String, String>): String {
            try {
                val payload = Payload(this@HttpApi.metadata + metadata, data)
                val bytes = json.encodeToString(serializer, payload).encodeToByteArray()
                val id = client.post("$path/$algorithm/$params") {
                    setBody(ByteArrayContent(bytes))
                }.bodyAsText()
                println("save: $path/$algorithm/$params -> $id | $metadata")
                return id
            } catch (cause: Throwable) {
                println("save[FAILED]: $path/$algorithm/$params | $metadata")
                throw cause
            }
        }

        override suspend fun get(algorithm: String, params: String, id: String): Payload<T> {
            try {
                val text = client.get("$path/$algorithm/$params/$id").bodyAsText()
                val payload = json.decodeFromString(serializer, text)
                println("get: $path/$algorithm/$params/$id | ${payload.metadata}")
                return payload
            } catch (cause: Throwable) {
                println("get[FAILED]: $path/$algorithm/$params/$id")
                throw cause
            }
        }

        override suspend fun getAll(algorithm: String, params: String): List<Payload<T>> {
            println("getAll: $path/$algorithm/$params")
            val channel = client.get("$path/$algorithm/$params").bodyAsChannel()
            return buildList {
                while (true) {
                    val lengthPacket = channel.readRemaining(4)
                    if (lengthPacket.remaining == 0L) break
                    val length = lengthPacket.readInt()
                    val bytes = channel.readPacket(length).readBytes().decodeToString()
                    add(json.decodeFromString(serializer, bytes))
                }
            }
        }
    }
}
