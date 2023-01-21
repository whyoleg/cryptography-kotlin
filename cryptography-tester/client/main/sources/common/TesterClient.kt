package dev.whyoleg.cryptography.tester.client

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.content.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.flow.*

object TesterClient {

    private val client = HttpClient {
        install(DefaultRequest) {
            port = 9000
        }
    }

    suspend fun saveParameters(algorithm: String, path: String, bytes: ByteArray): String =
        save("$algorithm/$path", bytes)

    fun getParameters(algorithm: String, path: String): Flow<Pair<String, ByteArray>> =
        get("$algorithm/$path")

    suspend fun saveData(algorithm: String, path: String, parametersId: String, bytes: ByteArray): String =
        save("$algorithm/$path/$parametersId/data", bytes)

    fun getData(algorithm: String, path: String, parametersId: String): Flow<Pair<String, ByteArray>> =
        get("$algorithm/$path/$parametersId/data")

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
