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
import io.ktor.util.pipeline.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import java.nio.file.*
import java.util.concurrent.atomic.*
import kotlin.io.path.*

@OptIn(ExperimentalPathApi::class)
fun main() {
    //TODO: get from args
    val rootPath = Path("cryptography-tests/cryptography-test-vectors").also(Path::deleteRecursively)
    val instanceId = "1"

    embeddedServer(Netty, port = 9000) {
        install(CallLogging)
        install(CORS) {
            anyHost()
        }
        routing {
            fun Routing.storage(name: String, shortName: String) = route(name) {
                fun ApplicationCall.directory() =
                    rootPath
                        .resolve(name)
                        .resolve(parameters["algorithm"]!!)
                        .resolve(parameters["params"]!!)

                val idGenerator = AtomicInteger()
                route("{algorithm}/{params}") {
                    post {
                        val request = call.request.receiveChannel().readRemaining().readBytes()
                        val id = "$shortName-$instanceId-${idGenerator.incrementAndGet()}"

                        call.directory()
                            .createDirectories()
                            .resolve("$id.json")
                            .writeBytes(request, StandardOpenOption.CREATE_NEW)

                        call.respondText(id)
                    }
                    get {
                        call.respondBytesWriter {
                            call.directory().forEachDirectoryEntry {
                                val content = it.readBytes()
                                writeInt(content.size)
                                writeFully(content)
                            }
                        }
                    }
                    get("{id}") {
                        val id = call.parameters["id"]!!

                        call.respondBytes(
                            call.directory()
                                .resolve("$id.json")
                                .readBytes()
                        )
                    }
                }
            }

            storage("keys", "k")
            storage("key-pairs", "kp")
            storage("ciphers", "c")
            storage("signatures", "s")
            storage("digests", "d")
        }
    }.start(wait = true)
}
