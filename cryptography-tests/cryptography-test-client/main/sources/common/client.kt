package dev.whyoleg.cryptography.test.client

import dev.whyoleg.cryptography.test.api.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.websocket.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.*
import io.ktor.serialization.kotlinx.protobuf.*
import io.ktor.util.reflect.*
import kotlinx.serialization.*
import kotlinx.serialization.protobuf.*

@OptIn(ExperimentalSerializationApi::class)
private val client = HttpClient {
    install(ContentNegotiation) {
        protobuf()
    }
    install(WebSockets) {
        contentConverter = KotlinxWebsocketSerializationConverter(ProtoBuf)
    }
    install(DefaultRequest) {
        port = 9000
        contentType(ContentType.Application.ProtoBuf)
    }
}

class ApiClient(
    val platform: Platform,
    val engine: Engine,
) {
    private inline fun <reified T> api(path: String) = SubApi<T>(path, typeInfo<EncodedData<T>>())

    val keys = api<EncodedKey>("keys")
    val keyPairs = api<EncodedKeyPair>("key-pairs")
    val digests = api<EncodedDigest>("digests")
    val signatures = api<EncodedSignature>("signatures")
    val ciphers = api<EncodedCipher>("ciphers")

    inner class SubApi<T> internal constructor(
        private val path: String,
        private val typeInfo: TypeInfo,
    ) {
        suspend fun save(algorithm: String, params: String, data: T): String {
            return client.post("$path/$algorithm/$params") {
                setBody(EncodedData(platform, engine, data), typeInfo)
            }.body<EncodedId>().id
        }

        suspend fun get(algorithm: String, params: String, id: String): EncodedData<T> {
            return client.get("$path/$algorithm/$params/$id").body(typeInfo)
        }
    }
}
