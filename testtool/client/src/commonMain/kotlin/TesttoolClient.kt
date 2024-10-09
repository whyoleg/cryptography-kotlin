/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.client

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.content.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.flow.*
import kotlinx.io.*

object TesttoolClient {

    object Compatibility {

        suspend fun saveParameters(algorithm: String, path: String, bytes: ByteArray): String =
            postData("compatibility/$algorithm/$path", bytes)

        fun getParameters(algorithm: String, path: String): Flow<Pair<String, ByteArray>> =
            getData("compatibility/$algorithm/$path")

        suspend fun saveData(algorithm: String, path: String, parametersId: String, bytes: ByteArray): String =
            postData("compatibility/$algorithm/$path/$parametersId/data", bytes)

        fun getData(algorithm: String, path: String, parametersId: String): Flow<Pair<String, ByteArray>> =
            getData("compatibility/$algorithm/$path/$parametersId/data")
    }
}

internal expect fun hostOverride(): String?

private val client = HttpClient {
    expectSuccess = true
    install(DefaultRequest) {
        host = hostOverride() ?: ""
        port = 9000
    }
    install(HttpRequestRetry)
}

internal suspend fun postData(path: String, bytes: ByteArray): String = client.post(path) {
    setBody(ByteArrayContent(bytes))
}.bodyAsText()

internal fun getData(path: String): Flow<Pair<String, ByteArray>> = flow {
    val channel = client.get(path).bodyAsChannel()
    while (true) {
        val idLength = channel.readIntOrNull() ?: break
        val id = channel.readPacket(idLength).readString()
        val contentLength = channel.readInt()
        val content = channel.readPacket(contentLength).readByteArray()
        emit(id to content)
    }
}

private suspend fun ByteReadChannel.readIntOrNull(): Int? {
    val packet = readRemaining(4)
    if (packet.remaining == 0L) return null
    return packet.readInt()
}