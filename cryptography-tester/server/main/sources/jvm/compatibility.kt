package dev.whyoleg.cryptography.tester.server

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import java.nio.file.*
import java.util.concurrent.atomic.*
import kotlin.io.path.*

fun Route.compatibility(
    instanceId: String,
    storagePath: Path,
): Route = route("compatibility/{algorithm}") {
    fun Route.storage(path: String, idPrefix: String): Route = route(path) {
        fun ApplicationCall.parametersPath() = storagePath / parameters["algorithm"]!! / path
        fun ApplicationCall.dataPath() = parametersPath() / parameters["parametersId"]!! / "data"
        fun AtomicInteger.generateId(kind: String) = "$instanceId-$idPrefix-$kind${incrementAndGet()}"

        val parametersIdGenerator = AtomicInteger()
        val dataIdGenerator = AtomicInteger()

        post {
            val id = parametersIdGenerator.generateId("P")
            call.saveFile(call.parametersPath().resolve(id), "parameters.json")
            call.respondText(id)
        }
        get {
            call.getFiles(call.parametersPath()) { name to resolve("parameters.json") }
        }
        route("{parametersId}/data") {
            post {
                val id = dataIdGenerator.generateId("D")
                call.saveFile(call.dataPath(), "$id.json")
                call.respondText(id)
            }
            get {
                call.getFiles(call.dataPath()) { nameWithoutExtension to this }
            }
        }
    }

    storage("keys", "K")
    storage("key-pairs", "KP")
    storage("digests", "D")
    storage("signatures", "S")
    storage("ciphers", "C")
}

private suspend fun ApplicationCall.saveFile(path: Path, name: String) {
    val bytes = request.receiveChannel().readRemaining().readBytes()

    path.createDirectories().resolve(name).writeBytes(bytes, StandardOpenOption.CREATE_NEW)
}

private suspend fun ApplicationCall.getFiles(path: Path, get: Path.() -> Pair<String, Path>) = respondBytesWriter {
    path.forEachDirectoryEntry { entry ->
        val (id, contentPath) = get(entry)
        val idBytes = id.encodeToByteArray()
        val contentBytes = contentPath.readBytes()
        writeInt(idBytes.size)
        writeFully(idBytes)
        writeInt(contentBytes.size)
        writeFully(contentBytes)
    }
}
