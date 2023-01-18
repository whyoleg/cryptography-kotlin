package dev.whyoleg.cryptography.test.vectors.server

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
    val rootPath = Path("cryptography-test-vectors/storage").also(Path::deleteRecursively)
    val instanceId = "1"

    embeddedServer(Netty, port = 9000) {
        install(CallLogging)
        install(CORS) { anyHost() }
        routing {
            route("{algorithm}") {
                fun Route.storage(path: String, idPrefix: String): Route = route(path) {
                    fun ApplicationCall.parametersPath() = rootPath / parameters["algorithm"]!! / path
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
        }
    }.start(wait = true)
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
