/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.server

import dev.whyoleg.cryptography.testtool.api.*
import io.ktor.serialization.kotlinx.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.*
import kotlinx.serialization.*
import java.io.*
import java.nio.file.*
import kotlin.io.path.*

fun startTesttoolServer(
    instanceId: String,
    storagePath: Path,
): Closeable {
    println("TesttoolServer: starting...")
    val server = startServer(storagePath)
    println("TesttoolServer: started")
    return Closeable {
        println("TesttoolServer: stopping...")
        server.stop()
        println("TesttoolServer: stopped")
    }
}

@OptIn(ExperimentalSerializationApi::class)
private fun startServer(storagePath: Path) = embeddedServer(CIO, 9000) {
    install(CallLogging) { disableDefaultColors() }
    install(CORS) { anyHost() }
    install(WebSockets) {
        contentConverter = KotlinxWebsocketSerializationConverter(ConfiguredCbor)
    }
    routing {
        webSocket("operations") {
            try {
                while (true) {
                    when (val operation = receiveDeserialized<Operation>()) {
                        is SaveParameters -> {
                            (storagePath / "compatibility" / operation.algorithm / operation.path / "parameters")
                                .createDirectories()
                                .resolve("${operation.id}.cbor")
                                .writeBytes(operation.payload, StandardOpenOption.CREATE_NEW)
                        }
                        is SaveData       -> {
                            (storagePath / "compatibility" / operation.algorithm / operation.path / "data" / operation.parametersId)
                                .createDirectories()
                                .resolve("${operation.id}.cbor")
                                .writeBytes(operation.payload, StandardOpenOption.CREATE_NEW)
                        }
                        is GetParameters  -> launch {
                            val path = (storagePath / "compatibility" / operation.algorithm / operation.path / "parameters")
                            if (path.exists()) path.forEachDirectoryEntry { entry ->
                                if (!entry.isRegularFile()) {
                                    println("$entry is not supported")
                                    return@forEachDirectoryEntry
                                }
                                sendSerialized<OperationResult>(
                                    GetOperationResultItem(operation.requestId, entry.nameWithoutExtension, entry.readBytes())
                                )
                            }
                            sendSerialized<OperationResult>(
                                GetOperationResultDone(operation.requestId)
                            )
                        }
                        is GetData        -> launch {
                            val path =
                                (storagePath / "compatibility" / operation.algorithm / operation.path / "data" / operation.parametersId)
                            if (path.exists()) launch {
                                path.forEachDirectoryEntry { entry ->
                                    if (!entry.isRegularFile()) {
                                        println("$entry is not supported")
                                        return@forEachDirectoryEntry
                                    }
                                    sendSerialized<OperationResult>(
                                        GetOperationResultItem(operation.requestId, entry.nameWithoutExtension, entry.readBytes())
                                    )
                                }
                                sendSerialized<OperationResult>(
                                    GetOperationResultDone(operation.requestId)
                                )
                            }
                        }
                    }
                }
            } catch (_: ClosedReceiveChannelException) {
                // do nothing, we just stopped saving
            }
        }
    }
}.start()
