/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.client

import dev.whyoleg.cryptography.testtool.api.*
import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.websocket.*
import io.ktor.serialization.kotlinx.*
import io.ktor.websocket.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.*

class TesttoolClient {
    @OptIn(ExperimentalSerializationApi::class)
    private val client = HttpClient {
        expectSuccess = true
        install(DefaultRequest) {
            host = hostOverride() ?: ""
        }
        install(WebSockets) {
            contentConverter = KotlinxWebsocketSerializationConverter(ConfiguredCbor)
        }
    }

    private val getChannels = mutableMapOf<String, Channel<GetOperationResultItem>>()
    private val session = client.async(start = CoroutineStart.LAZY) {
        val session = client.webSocketSession(path = "operations", port = 9000)
        client.launch {
            try {
                while (true) {
                    when (val result = session.receiveDeserialized<OperationResult>()) {
                        is GetOperationResultDone -> requireNotNull(getChannels.remove(result.requestId)) {
                            "Channel with id ${result.requestId} not found"
                        }.close()
                        is GetOperationResultItem -> getChannels.getValue(result.requestId).send(result)
                    }
                }
            } catch (_: ClosedReceiveChannelException) {
                // do nothing, we just stopped saving
            }
        }
        session
    }

    suspend fun save(operation: SaveOperation) {
        session.await().sendSerialized(operation)
    }

    fun get(operation: GetOperation): Flow<GetOperationResultItem> {
        val channel = Channel<GetOperationResultItem>(Channel.UNLIMITED)
        require(getChannels.put(operation.requestId, channel) == null) {
            "Channel with id ${operation.requestId} already exists"
        }
        return channel.consumeAsFlow().onStart {
            session.await().sendSerialized(operation)
        }
    }

    suspend fun cleanup(): Unit = withContext(NonCancellable) {
        session.await().let { session ->
            session.close()
            session.incoming.cancel()
            session.coroutineContext.job.join()
        }

        client.close()
        client.coroutineContext.job.join()
    }
}

internal expect fun hostOverride(): String?
