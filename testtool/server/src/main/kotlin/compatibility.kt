/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.server

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import java.nio.file.*
import java.util.concurrent.atomic.*
import kotlin.io.path.*

internal fun Route.routes(
    instanceId: String,
    storagePath: Path,
) {
    val parametersIdGenerator = AtomicInteger()
    val dataIdGenerator = AtomicInteger()

    route("compatibility/{algorithm}") {
        fun Route.storage(path: String): Route = route(path) {
            fun ApplicationCall.parametersPath() = storagePath / "compatibility" / parameters["algorithm"]!! / path
            fun ApplicationCall.dataPath() = parametersPath() / parameters["parametersId"]!! / "data"
            fun AtomicInteger.generateId() = "$instanceId-${incrementAndGet()}"

            post {
                val id = parametersIdGenerator.generateId()
                call.saveFile(call.parametersPath().resolve(id), "parameters.json")
                call.respondText(id)
            }
            get {
                call.getFiles(call.parametersPath()) { name to resolve("parameters.json") }
            }
            route("{parametersId}/data") {
                post {
                    val id = dataIdGenerator.generateId()
                    call.saveFile(call.dataPath(), "$id.json")
                    call.respondText(id)
                }
                get {
                    call.getFiles(call.dataPath()) { nameWithoutExtension to this }
                }
            }
        }

        storage("keys")
        storage("keyPairs")
        storage("digests")
        storage("signatures")
        storage("ciphers")
        storage("sharedSecrets")
        storage("derivedSecrets")
    }
}

private suspend fun ApplicationCall.saveFile(path: Path, name: String) {
    val bytes = request.receiveChannel().readRemaining().readBytes()

    path.createDirectories().resolve(name).writeBytes(bytes, StandardOpenOption.CREATE_NEW)
}

private suspend fun ApplicationCall.getFiles(path: Path, get: Path.() -> Pair<String, Path>) = respondBytesWriter {
    if (!path.exists()) return@respondBytesWriter

    path.forEachDirectoryEntry { entry ->
        val (id, contentPath) = get(entry)
        if (!contentPath.isRegularFile()) {
            println("$contentPath is not supported")
            return@forEachDirectoryEntry
        }
        val idBytes = id.encodeToByteArray()
        val contentBytes = contentPath.readBytes()
        writeInt(idBytes.size)
        writeFully(idBytes)
        writeInt(contentBytes.size)
        writeFully(contentBytes)
    }
}
