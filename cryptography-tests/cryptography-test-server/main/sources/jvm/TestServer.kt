package dev.whyoleg.cryptography.test.server

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import java.nio.file.*
import java.util.concurrent.atomic.*
import kotlin.io.path.*

@OptIn(ExperimentalPathApi::class)
fun main() {
    //TODO: get from args
    val rootPath = Path("cryptography-tests/cryptography-test-vectors-storage").also(Path::deleteRecursively)
    val instanceId = "1"

    embeddedServer(Netty, port = 9000) {
        install(CallLogging)
        install(CORS) { anyHost() }
        routing {
            route("{algorithm}") {
                fun Route.storage(path: String, idPrefix: String): Route = route(path) {
                    fun ApplicationCall.metaPath() = rootPath / parameters["algorithm"]!! / path
                    fun ApplicationCall.dataPath() = metaPath() / parameters["id"]!! / "data"

                    val metaIdGenerator = AtomicInteger()
                    val dataIdGenerator = AtomicInteger()

                    get { call.getFiles(call.metaPath(), "meta.json") }
                    post { call.saveFile(call.metaPath(), "meta.json", "M-$idPrefix-$instanceId-${metaIdGenerator.incrementAndGet()}") }
                    route("{id}/data") {
                        get { call.getFiles(call.dataPath(), "data.json") }
                        post { call.saveFile(call.dataPath(), "data.json", "D-$idPrefix-$instanceId-${dataIdGenerator.incrementAndGet()}") }
                    }
                }

                storage("keys", "k")
                storage("key-pairs", "kp")
                storage("digests", "d")
                storage("signatures", "s")
                storage("ciphers", "c")
                storage("derived-secrets", "ds")
            }
        }
    }.start(wait = true)
}

private suspend fun ApplicationCall.saveFile(path: Path, name: String, id: String) {
    val bytes = request.receiveChannel().readRemaining().readBytes()

    path.resolve(id)
        .createDirectories()
        .resolve(name)
        .writeBytes(bytes, StandardOpenOption.CREATE_NEW)

    respondText(id)
}

private suspend fun ApplicationCall.getFiles(path: Path, name: String) = respondBytesWriter {
    path.forEachDirectoryEntry { directory ->
        val idBytes = directory.name.encodeToByteArray()
        val contentBytes = directory.resolve(name).readBytes()
        writeInt(idBytes.size)
        writeFully(idBytes)
        writeInt(contentBytes.size)
        writeFully(contentBytes)
    }
}
