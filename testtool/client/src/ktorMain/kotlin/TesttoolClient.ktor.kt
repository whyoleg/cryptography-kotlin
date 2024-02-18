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

private val client = HttpClient {
    expectSuccess = true
    install(DefaultRequest) {
        host = hostOverride() ?: ""
        port = 9000
    }
    install(HttpRequestRetry)
}

internal actual suspend fun postData(path: String, bytes: ByteArray): String = client.post(path) {
    setBody(ByteArrayContent(bytes))
}.bodyAsText()

internal actual fun getData(path: String): Flow<Pair<String, ByteArray>> = flow {
    val channel = client.get(path).bodyAsChannel()
    while (true) {
        val idLength = channel.readIntOrNull() ?: break
        val id = channel.readPacket(idLength).readText()
        val contentLength = channel.readInt()
        val content = channel.readPacket(contentLength).readBytes()
        emit(id to content)
    }
}

private suspend fun ByteReadChannel.readIntOrNull(): Int? {
    val packet = readRemaining(4)
    if (packet.remaining == 0L) return null
    return packet.readInt()
}
