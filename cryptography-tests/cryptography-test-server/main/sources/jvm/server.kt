package dev.whyoleg.cryptography.test.server

import dev.whyoleg.cryptography.test.api.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.*
import io.ktor.serialization.kotlinx.protobuf.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import kotlinx.serialization.*
import kotlinx.serialization.protobuf.*
import java.nio.file.*
import java.util.concurrent.atomic.*
import kotlin.io.path.*

@OptIn(ExperimentalSerializationApi::class, ExperimentalPathApi::class)
fun main() {
    //TODO: get from args
    val rootPath = Path("cryptography-tests/cryptography-test-server/temp").also(Path::deleteRecursively)
    val instanceId = "1"

    embeddedServer(Netty, port = 9000) {
        install(ContentNegotiation) {
            protobuf()
        }
        install(WebSockets) {
            contentConverter = KotlinxWebsocketSerializationConverter(ProtoBuf)
        }
        install(CallLogging)

        routing {
            fun Routing.storage(name: String, shortName: String) = route(name) {
                val idGenerator = AtomicInteger()
                route("{algorithm}/{params}") {
                    post {
                        val algorithm = call.parameters["algorithm"]!!
                        val params = call.parameters["params"]!!
                        val request = call.receive<ByteArray>()

                        val id = "$shortName-$instanceId-${idGenerator.incrementAndGet()}"

                        rootPath
                            .resolve(name)
                            .resolve(algorithm)
                            .resolve(params)
                            .createDirectories()
                            .resolve("$id.pb")
                            .writeBytes(request, StandardOpenOption.CREATE_NEW)

                        call.respond(EncodedId(id))
                    }
                    get("{id}") {
                        val algorithm = call.parameters["algorithm"]!!
                        val params = call.parameters["params"]!!
                        val id = call.parameters["id"]!!

                        call.respondBytes(
                            rootPath
                                .resolve(name)
                                .resolve(algorithm)
                                .resolve(params)
                                .resolve("$id.pb")
                                .readBytes(),
                            ContentType.Application.ProtoBuf,
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
